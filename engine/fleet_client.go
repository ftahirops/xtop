package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// ─── FleetClient — agent-side push client ────────────────────────────────────
//
// Responsibilities:
//   1. Build heartbeats from each tick's AnalysisResult + Snapshot.
//   2. Detect incident transitions (Start → Update → Resolve) and post FleetIncident.
//   3. Queue payloads to local disk when hub is unreachable; replay on recovery.
//   4. Send in a separate goroutine so the RCA tick never blocks on network.

// FleetClient pushes heartbeats and incidents to an xtop hub.
// FleetQuality is the per-agent incident quality gate. It exists because
// the raw RCA signal flaps near the OK/Degraded boundary — a box briefly
// over threshold for one tick produces a pure-noise "incident" that's
// useless to operators and floods the hub's Postgres. The defaults below
// suppress 0%-score / 0%-confidence flaps; operators can tighten them
// further via XTOP_FLEET_QUALITY_* env vars.
type FleetQuality struct {
	MinPeakScore     int           // below this → never emit (default 30)
	MinConfidence    int           // below this → never emit (default 40)
	MinStartTicks    int           // consecutive bad ticks before IncidentStarted (default 3)
	MinEscalationGap time.Duration // min time between signature-flip escalations (default 15s)
}

// defaultFleetQuality returns the baked-in policy with env overrides
// applied. Read once at client construction; caller shouldn't mutate.
func defaultFleetQuality() FleetQuality {
	q := FleetQuality{
		MinPeakScore:     30,
		MinConfidence:    40,
		MinStartTicks:    3,
		MinEscalationGap: 15 * time.Second,
	}
	if v, err := strconv.Atoi(os.Getenv("XTOP_FLEET_QUALITY_MIN_SCORE")); err == nil && v >= 0 {
		q.MinPeakScore = v
	}
	if v, err := strconv.Atoi(os.Getenv("XTOP_FLEET_QUALITY_MIN_CONF")); err == nil && v >= 0 {
		q.MinConfidence = v
	}
	if v, err := strconv.Atoi(os.Getenv("XTOP_FLEET_QUALITY_MIN_TICKS")); err == nil && v > 0 {
		q.MinStartTicks = v
	}
	if v, err := strconv.Atoi(os.Getenv("XTOP_FLEET_QUALITY_ESC_GAP_SEC")); err == nil && v > 0 {
		q.MinEscalationGap = time.Duration(v) * time.Second
	}
	return q
}

type FleetClient struct {
	cfg        model.FleetAgentConfig
	httpClient *http.Client
	agentID    string
	quality    FleetQuality

	// Incident tracking — we need to know when an incident started so we can
	// post IncidentStarted once, then IncidentUpdated as it evolves.
	incMu            sync.Mutex
	activeIncidentID string
	activeSignature  string
	activeStartedAt  time.Time
	activePeakScore  int

	// Quality gate state
	consecutiveBadTicks int       // sustained-above-bar counter
	emittedStart        bool      // did we actually tell the hub about the current incident?
	lastEscalationAt    time.Time // rate-limits signature-flip noise

	// Outgoing queue (sent sequentially from one worker goroutine).
	// Worker pulls from memQueue first, then from disk queue on reconnect.
	queueMu   sync.Mutex
	memQueue  []queuedMsg
	quitCh    chan struct{}
	workerWG  sync.WaitGroup
	queuePath string
	maxQueue  int
}

type queuedMsg struct {
	Endpoint string          `json:"endpoint"`
	Body     json.RawMessage `json:"body"`
	Enqueued time.Time       `json:"enqueued"`
}

// NewFleetClient creates a client. Returns nil if cfg.HubURL is empty.
func NewFleetClient(cfg model.FleetAgentConfig) *FleetClient {
	if cfg.HubURL == "" {
		return nil
	}
	if cfg.QueuePath == "" {
		home, _ := os.UserHomeDir()
		cfg.QueuePath = filepath.Join(home, ".xtop", "fleet-queue.jsonl")
	}
	if cfg.MaxQueueSize == 0 {
		cfg.MaxQueueSize = 10000
	}
	_ = os.MkdirAll(filepath.Dir(cfg.QueuePath), 0o755)

	fc := &FleetClient{
		cfg:       cfg,
		quitCh:    make(chan struct{}),
		queuePath: cfg.QueuePath,
		maxQueue:  cfg.MaxQueueSize,
		agentID:   loadOrCreateAgentID(),
		quality:   defaultFleetQuality(),
	}

	// HTTP client with short timeout — we never want to block RCA collection.
	fc.httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			MaxIdleConns:        5,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	fc.workerWG.Add(1)
	go fc.worker()
	return fc
}

// Close stops the worker goroutine and flushes any pending messages to disk.
func (fc *FleetClient) Close() {
	if fc == nil {
		return
	}
	close(fc.quitCh)
	fc.workerWG.Wait()
	fc.persistMemQueue()
}

// AgentID returns the stable agent identifier.
func (fc *FleetClient) AgentID() string { return fc.agentID }

// HubURL returns the hub URL the client is pushing to. Used for logging.
func (fc *FleetClient) HubURL() string { return fc.cfg.HubURL }

// Observe is called by the engine every tick with the current snapshot/result.
// It builds + queues a heartbeat, and emits incident records on state changes.
// This call must be non-blocking — any IO happens in the worker.
func (fc *FleetClient) Observe(snap *model.Snapshot, result *model.AnalysisResult, hostname, agentVersion string) {
	if fc == nil || snap == nil {
		return
	}
	hb := buildHeartbeat(snap, result, fc.agentID, hostname, agentVersion, fc.cfg.Tags)

	fc.incMu.Lock()
	// Incident state machine + quality gate.
	//
	// Policy (see FleetQuality type for defaults):
	//   - An incident must clear a quality bar (peak, confidence, sustained
	//     for N ticks) before we tell the hub anything. Below that bar, we
	//     still track the active incident LOCALLY — so recovery emits a
	//     Resolved only if we ever emitted Started.
	//   - Signature-flip escalations are rate-limited to prevent flap storms
	//     when RCA bounces between bottlenecks near threshold.
	//   - We never emit peak=0 confidence=0 payloads.
	if result != nil && result.Health > model.HealthOK {
		sig := fleetSignatureFromResult(result)
		peak := result.PrimaryScore
		conf := result.Confidence
		meetsBar := peak >= fc.quality.MinPeakScore && conf >= fc.quality.MinConfidence

		if meetsBar {
			fc.consecutiveBadTicks++
		} else {
			// Sub-threshold tick — the incident still counts as active
			// locally (so we don't re-start on the next above-bar tick),
			// but we reset the sustained counter so one-off spikes need
			// to clear the bar for MinStartTicks ticks again.
			fc.consecutiveBadTicks = 0
		}

		sustained := fc.consecutiveBadTicks >= fc.quality.MinStartTicks

		switch {
		case fc.activeIncidentID == "":
			// First above-OK tick of a (potential) incident. Assign a local
			// ID; only ANNOUNCE it to the hub once the quality bar is hit
			// and the incident is sustained.
			now := time.Now()
			fc.activeIncidentID = fc.newIncidentID(hostname, sig)
			fc.activeSignature = sig
			fc.activeStartedAt = now
			fc.activePeakScore = peak
			fc.emittedStart = false
			// Seed lastEscalationAt so a signature-flip within the gap
			// (counted from *incident start*) can't fire immediately.
			fc.lastEscalationAt = now
			hb.ActiveIncidentID = fc.activeIncidentID
			if sustained {
				inc := buildIncident(snap, result, fc.agentID, hostname, fc.activeIncidentID, fc.activeStartedAt, nil, model.IncidentStarted)
				fc.enqueueLocked(model.FleetEndpointIncident, inc)
				fc.emittedStart = true
			}

		case sig != fc.activeSignature && sig != "":
			// Bottleneck flipped. Only treat as a real escalation when:
			//   (a) the new signature also meets the quality bar, AND
			//   (b) at least MinEscalationGap has passed since the last
			//       transition (the current incident's start counts).
			now := time.Now()
			canEscalate := meetsBar &&
				now.Sub(fc.lastEscalationAt) >= fc.quality.MinEscalationGap
			if canEscalate {
				if fc.emittedStart {
					// Close the previous story cleanly.
					resolveInc := buildResolveIncidentOnly(fc.agentID, hostname, fc.activeIncidentID, fc.activeStartedAt, now, model.IncidentEscalated)
					fc.enqueueLocked(model.FleetEndpointIncident, resolveInc)
				}
				fc.activeIncidentID = fc.newIncidentID(hostname, sig)
				fc.activeSignature = sig
				fc.activeStartedAt = now
				fc.activePeakScore = peak
				fc.lastEscalationAt = now
				fc.consecutiveBadTicks = 1 // give the new signature a fresh sustained check
				fc.emittedStart = false
				hb.ActiveIncidentID = fc.activeIncidentID
				if sustained {
					inc := buildIncident(snap, result, fc.agentID, hostname, fc.activeIncidentID, fc.activeStartedAt, nil, model.IncidentStarted)
					fc.enqueueLocked(model.FleetEndpointIncident, inc)
					fc.emittedStart = true
				}
			} else {
				// Rate-limited OR sub-quality flip → silently update local
				// state, do not spam the hub. Signature stays the same for
				// next-tick comparison so we don't pretend this is stable.
				hb.ActiveIncidentID = fc.activeIncidentID
			}

		default:
			// Same bottleneck, still bad.
			hb.ActiveIncidentID = fc.activeIncidentID
			if sustained && !fc.emittedStart {
				// We were tracking but never announced — announce now.
				inc := buildIncident(snap, result, fc.agentID, hostname, fc.activeIncidentID, fc.activeStartedAt, nil, model.IncidentStarted)
				fc.enqueueLocked(model.FleetEndpointIncident, inc)
				fc.emittedStart = true
				fc.activePeakScore = peak
			} else if fc.emittedStart && peak > fc.activePeakScore {
				fc.activePeakScore = peak
				// Score got worse — hub wants to know.
				inc := buildIncident(snap, result, fc.agentID, hostname, fc.activeIncidentID, fc.activeStartedAt, nil, model.IncidentUpdated)
				fc.enqueueLocked(model.FleetEndpointIncident, inc)
			}
		}
	} else if fc.activeIncidentID != "" {
		// Health returned to OK. Only emit Resolved if we actually told the
		// hub about this incident; otherwise it never existed to the hub
		// and emitting a dangling Resolved would be noise.
		if fc.emittedStart {
			resolved := time.Now()
			inc := buildResolveIncidentOnly(fc.agentID, hostname, fc.activeIncidentID, fc.activeStartedAt, resolved, model.IncidentResolved)
			fc.enqueueLocked(model.FleetEndpointIncident, inc)
		}
		fc.activeIncidentID = ""
		fc.activeSignature = ""
		fc.activeStartedAt = time.Time{}
		fc.activePeakScore = 0
		fc.consecutiveBadTicks = 0
		fc.emittedStart = false
	}
	fc.incMu.Unlock()

	// Always send heartbeat
	fc.enqueue(model.FleetEndpointHeartbeat, hb)
}

// ─── Queue machinery ─────────────────────────────────────────────────────────

func (fc *FleetClient) enqueue(endpoint string, body interface{}) {
	fc.queueMu.Lock()
	defer fc.queueMu.Unlock()
	fc.enqueueLocked(endpoint, body)
}

func (fc *FleetClient) enqueueLocked(endpoint string, body interface{}) {
	data, err := json.Marshal(body)
	if err != nil {
		return
	}
	if len(fc.memQueue) >= fc.maxQueue {
		// Drop oldest — prefer fresh data over backlog
		fc.memQueue = fc.memQueue[1:]
	}
	fc.memQueue = append(fc.memQueue, queuedMsg{
		Endpoint: endpoint,
		Body:     data,
		Enqueued: time.Now(),
	})
}

func (fc *FleetClient) worker() {
	defer fc.workerWG.Done()

	// On startup, replay anything left on disk from a prior crash.
	fc.drainDiskQueue()

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-fc.quitCh:
			return
		case <-tick.C:
			fc.flushMemQueue()
		}
	}
}

func (fc *FleetClient) flushMemQueue() {
	fc.queueMu.Lock()
	if len(fc.memQueue) == 0 {
		fc.queueMu.Unlock()
		return
	}
	batch := fc.memQueue
	fc.memQueue = nil
	fc.queueMu.Unlock()

	var failed []queuedMsg
	for _, m := range batch {
		if err := fc.post(m.Endpoint, m.Body); err != nil {
			failed = append(failed, m)
		}
	}
	if len(failed) > 0 {
		fc.queueMu.Lock()
		// Put failures back at head; new messages stay at tail.
		fc.memQueue = append(failed, fc.memQueue...)
		// If the queue gets really long, spill oldest to disk.
		if len(fc.memQueue) > fc.maxQueue/2 {
			spill := fc.memQueue[:len(fc.memQueue)-fc.maxQueue/2]
			fc.memQueue = fc.memQueue[len(spill):]
			fc.queueMu.Unlock()
			fc.persistBatch(spill)
			return
		}
		fc.queueMu.Unlock()
	}
}

func (fc *FleetClient) persistMemQueue() {
	fc.queueMu.Lock()
	batch := fc.memQueue
	fc.memQueue = nil
	fc.queueMu.Unlock()
	if len(batch) > 0 {
		fc.persistBatch(batch)
	}
}

func (fc *FleetClient) persistBatch(batch []queuedMsg) {
	f, err := os.OpenFile(fc.queuePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, m := range batch {
		_ = enc.Encode(m)
	}
}

func (fc *FleetClient) drainDiskQueue() {
	f, err := os.Open(fc.queuePath)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var ok []queuedMsg
	for scanner.Scan() {
		var m queuedMsg
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			continue
		}
		// Skip stale messages (>1h old)
		if time.Since(m.Enqueued) > time.Hour {
			continue
		}
		ok = append(ok, m)
	}
	// Try to post everything; whatever fails goes back to disk.
	var failed []queuedMsg
	for _, m := range ok {
		if err := fc.post(m.Endpoint, m.Body); err != nil {
			failed = append(failed, m)
		}
	}
	if len(failed) > 0 {
		// Rewrite the queue file with only failed entries.
		tmp := fc.queuePath + ".tmp"
		if f2, err := os.Create(tmp); err == nil {
			enc := json.NewEncoder(f2)
			for _, m := range failed {
				_ = enc.Encode(m)
			}
			f2.Close()
			_ = os.Rename(tmp, fc.queuePath)
		}
	} else {
		_ = os.Remove(fc.queuePath)
	}
}

func (fc *FleetClient) post(endpoint string, body []byte) error {
	url := fc.cfg.HubURL + endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if fc.cfg.Token != "" {
		req.Header.Set(model.FleetAuthHeader, fc.cfg.Token)
	}
	resp, err := fc.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("hub returned status %d", resp.StatusCode)
	}
	return nil
}

// ─── Builders ────────────────────────────────────────────────────────────────

func buildHeartbeat(snap *model.Snapshot, result *model.AnalysisResult, agentID, hostname, version string, tags []string) model.FleetHeartbeat {
	hb := model.FleetHeartbeat{
		Hostname:     hostname,
		AgentID:      agentID,
		Tags:         tags,
		AgentVersion: version,
		Timestamp:    time.Now(),
		NumCPUs:      snap.Global.CPU.NumCPUs,
	}
	if snap.SysInfo != nil {
		hb.Kernel = snap.SysInfo.Kernel
		hb.OS = snap.SysInfo.OS
	}
	if result != nil {
		hb.Health = result.Health
		hb.PrimaryBottleneck = result.PrimaryBottleneck
		hb.PrimaryScore = result.PrimaryScore
		hb.Confidence = result.Confidence
		hb.CulpritProcess = result.PrimaryProcess
		hb.CulpritPID = result.PrimaryPID
		hb.CulpritApp = result.PrimaryAppName
		// Self-resource reporting — published whenever the engine has
		// populated result.Guard (i.e. ResourceGuard is enabled).
		// Operators see xtop's own footprint per host on the dashboard.
		if result.Guard != nil {
			hb.XtopOwnCPUPct = result.Guard.OwnCPUPct
			hb.XtopGuardLevel = result.Guard.Level
		}
		hb.XtopOwnRSSMB = readSelfRSSMB()
		hb.XtopMode = xtopModeLabel(snap)
	}
	if snap.Global.Memory.Total > 0 {
		hb.MemTotalBytes = snap.Global.Memory.Total
		hb.MemUsedPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}
	hb.LoadAvg1 = snap.Global.CPU.LoadAvg.Load1
	return hb
}

// readSelfRSSMB parses /proc/self/status for VmRSS. Returns 0 on any
// error — the heartbeat ships without the field rather than failing.
// Cheap (<100 µs) and called once per heartbeat.
func readSelfRSSMB() float64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	s := string(data)
	idx := strings.Index(s, "VmRSS:")
	if idx < 0 {
		return 0
	}
	rest := s[idx+len("VmRSS:"):]
	// Skip whitespace, parse number, ignore unit.
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	kb, err := strconv.ParseFloat(rest[:end], 64)
	if err != nil {
		return 0
	}
	// /proc/self/status reports VmRSS in kB.
	return kb / 1024.0
}

// xtopModeLabel reports whether this agent is running Lean or Rich. Read
// from a sentinel hint that's set on the snapshot's CollectionHealth or,
// failing that, falls back to "rich" since the rich path is the default.
func xtopModeLabel(snap *model.Snapshot) string {
	if snap == nil || snap.CollectionHealth == nil {
		return "rich"
	}
	// We use Total < 12 as a proxy: the lean collector list has 9
	// collectors; rich has 21+. Approximate but cheap and correct in
	// practice for our two builds.
	if snap.CollectionHealth.Total > 0 && snap.CollectionHealth.Total < 12 {
		return "lean"
	}
	return "rich"
}

func buildIncident(snap *model.Snapshot, result *model.AnalysisResult, agentID, hostname, incID string, startedAt time.Time, resolvedAt *time.Time, kind model.IncidentUpdateType) model.FleetIncident {
	inc := model.FleetIncident{
		Hostname:   hostname,
		AgentID:    agentID,
		IncidentID: incID,
		StartedAt:  startedAt,
		ResolvedAt: resolvedAt,
		Timestamp:  time.Now(),
		UpdateType: kind,
	}
	if result != nil {
		inc.Bottleneck = result.PrimaryBottleneck
		inc.PeakScore = result.PrimaryScore
		inc.Confidence = result.Confidence
		inc.Health = result.Health
		inc.Culprit = result.PrimaryProcess
		inc.CulpritPID = result.PrimaryPID
		inc.CulpritApp = result.PrimaryAppName
		inc.Signature = fleetSignatureFromResult(result)
		inc.Diff = result.IncidentDiff
		// Lifecycle (TODO #5): populated from result echo of recorder state.
		inc.State = result.IncidentState
		inc.ConfirmedAt = result.IncidentConfirmedAt
		if len(result.Changes) > 0 {
			n := len(result.Changes)
			if n > 20 {
				n = 20
			}
			inc.ChangesAtConfirm = append([]model.SystemChange(nil), result.Changes[:n]...)
		}
		inc.FleetPeersAtConfirm = result.CrossHostCorrelation
		if result.Narrative != nil {
			inc.RootCause = result.Narrative.RootCause
			inc.Impact = result.Narrative.Impact
			inc.Pattern = result.Narrative.Pattern
			if len(result.Narrative.Evidence) > 0 {
				n := 5
				if len(result.Narrative.Evidence) < n {
					n = len(result.Narrative.Evidence)
				}
				inc.Evidence = append([]string(nil), result.Narrative.Evidence[:n]...)
			}
		}
	}
	// Top processes — pull from snap (already sorted/capped by the collector)
	if snap != nil && len(snap.Processes) > 0 {
		limit := 10
		if len(snap.Processes) < limit {
			limit = len(snap.Processes)
		}
		for i := 0; i < limit; i++ {
			p := snap.Processes[i]
			inc.TopProcesses = append(inc.TopProcesses, model.FleetProcess{
				PID: p.PID, Comm: p.Comm, RSS: p.RSS, State: p.State,
			})
		}
	}
	return inc
}

// buildResolveIncidentOnly constructs a minimal "resolved" incident — we don't
// need full evidence, just the close event so the hub can mark the record.
func buildResolveIncidentOnly(agentID, hostname, incID string, startedAt, resolvedAt time.Time, kind model.IncidentUpdateType) model.FleetIncident {
	return model.FleetIncident{
		Hostname:   hostname,
		AgentID:    agentID,
		IncidentID: incID,
		StartedAt:  startedAt,
		ResolvedAt: &resolvedAt,
		Timestamp:  time.Now(),
		UpdateType: kind,
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (fc *FleetClient) newIncidentID(hostname, signature string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%d-%s-%s", hostname, time.Now().Unix(), shortHash(signature), hex.EncodeToString(b))
}

func shortHash(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

// fleetSignatureFromResult builds a stable signature of the incident for matching
// across the fleet. Same bottleneck + top-3 evidence IDs = same signature.
//
// NOTE: mirrors signatureFromResult() in rca_history.go but lives here to avoid
// a circular import. The two must stay in sync.
func fleetSignatureFromResult(result *model.AnalysisResult) string {
	if result == nil || len(result.RCA) == 0 {
		return ""
	}
	sig := result.PrimaryBottleneck + "|"
	var ids []string
	for _, rca := range result.RCA {
		if rca.Bottleneck != result.PrimaryBottleneck {
			continue
		}
		for _, ev := range rca.EvidenceV2 {
			if ev.Strength > 0.35 {
				ids = append(ids, ev.ID)
			}
		}
		break
	}
	// Sort for stability
	for i := 0; i < len(ids)-1; i++ {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] > ids[j] {
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
	if len(ids) > 3 {
		ids = ids[:3]
	}
	for _, id := range ids {
		sig += id + ","
	}
	return sig
}

// loadOrCreateAgentID reads ~/.xtop/agent-id or creates a fresh UUID on first run.
func loadOrCreateAgentID() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return randomID()
	}
	path := filepath.Join(home, ".xtop", "agent-id")
	if data, err := os.ReadFile(path); err == nil {
		id := string(bytes.TrimSpace(data))
		if id != "" {
			return id
		}
	}
	id := randomID()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(id), 0o600)
	return id
}

func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to time-based if random fails (extremely unlikely)
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
