package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ftahirops/xtop/model"
)

// TraceMode controls when a TraceArmer dumps a trace.
type TraceMode int

const (
	TraceModeOff         TraceMode = 0
	TraceModeNext        TraceMode = 1 // dump the next tick, then disarm
	TraceModeOnConfirmed TraceMode = 2 // dump on every Suspected→Confirmed transition
)

// TraceArmer captures full A→Z reasoning of a single tick into one JSON + one
// markdown file in ~/.xtop/traces/. It is the user-facing verification tool:
// every claim in the verdict has a line of evidence in the trace, and the
// markdown reads like a sysadmin's notebook.
//
// This is NOT a continuous trace stream — that would be unmanageable in
// production at 20 verdicts/min/host. It is arm-once or transition-only.
//
// Activation: env at process start (XTOP_TRACE_NEXT=1 / XTOP_TRACE_ON_CONFIRMED=1)
// or programmatically via Arm(). Each TraceModeNext dump self-disarms.
type TraceArmer struct {
	mode atomic.Int32

	mu                sync.Mutex
	dir               string
	lastConfirmedSig  string // last signature we dumped for, to avoid duplicates
	lastConfirmedDump time.Time
}

// NewTraceArmer reads XTOP_TRACE_* env to decide initial mode. dir defaults to
// ~/.xtop/traces if empty.
func NewTraceArmer(dir string) *TraceArmer {
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".xtop", "traces")
		} else {
			dir = "/tmp/xtop-traces"
		}
	}
	t := &TraceArmer{dir: dir}
	switch {
	case os.Getenv("XTOP_TRACE_NEXT") == "1":
		t.mode.Store(int32(TraceModeNext))
	case os.Getenv("XTOP_TRACE_ON_CONFIRMED") == "1":
		t.mode.Store(int32(TraceModeOnConfirmed))
	}
	return t
}

// Arm sets the mode programmatically. Used by `xtop trace --once`.
func (t *TraceArmer) Arm(m TraceMode) {
	if t == nil {
		return
	}
	t.mode.Store(int32(m))
}

// ArmTraceNext arms the trace armer to dump on the next tick. CLI helper.
func (e *Engine) ArmTraceNext() {
	if e == nil || e.traceArmer == nil {
		return
	}
	e.traceArmer.Arm(TraceModeNext)
}

// ArmTraceOnConfirmed arms continuous Confirmed-transition dumps. CLI helper.
func (e *Engine) ArmTraceOnConfirmed() {
	if e == nil || e.traceArmer == nil {
		return
	}
	e.traceArmer.Arm(TraceModeOnConfirmed)
}

// Mode reports the current mode.
func (t *TraceArmer) Mode() TraceMode {
	if t == nil {
		return TraceModeOff
	}
	return TraceMode(t.mode.Load())
}

// MaybeDump is called every Tick. Decides whether to write a trace based on
// mode + lifecycle state, and writes both the .json and .md files when so.
func (t *TraceArmer) MaybeDump(
	snap *model.Snapshot,
	rates *model.RateSnapshot,
	result *model.AnalysisResult,
	hist *History,
	active *RCAIncident,
) {
	if t == nil || result == nil {
		return
	}
	mode := TraceMode(t.mode.Load())
	if mode == TraceModeOff {
		return
	}

	switch mode {
	case TraceModeNext:
		t.write(snap, rates, result, hist, active)
		t.mode.Store(int32(TraceModeOff)) // self-disarm
	case TraceModeOnConfirmed:
		// Only dump on a fresh Suspected→Confirmed transition. Dedupe by signature.
		if active == nil || active.State != IncidentConfirmed {
			return
		}
		t.mu.Lock()
		dup := active.Signature == t.lastConfirmedSig &&
			time.Since(t.lastConfirmedDump) < 60*time.Second
		t.mu.Unlock()
		if dup {
			return
		}
		t.write(snap, rates, result, hist, active)
		t.mu.Lock()
		t.lastConfirmedSig = active.Signature
		t.lastConfirmedDump = time.Now()
		t.mu.Unlock()
	}
}

// TraceFile is the on-disk JSON shape. Stable enough for tooling to consume,
// but not yet a public API; field names may shift.
type TraceFile struct {
	Schema    string    `json:"schema"`
	WrittenAt time.Time `json:"written_at"`
	Hostname  string    `json:"hostname,omitempty"`

	// Inputs the engine actually consulted this tick.
	Inputs traceInputs `json:"inputs"`

	// Per-domain analysis.
	Domains []traceDomain `json:"domains"`

	// Cross-domain analysis.
	Correlations []model.MetricCorrelation  `json:"correlations,omitempty"`
	Blame        []model.BlameEntry         `json:"blame,omitempty"`
	CausalChain  string                     `json:"causal_chain,omitempty"`
	AppAnomalies  []model.AppBehaviorAnomaly `json:"app_anomalies,omitempty"`
	DriftWarnings []model.DegradationWarning `json:"drift_warnings,omitempty"`
	Probes        []model.ProbeResult        `json:"probes,omitempty"`
	Changes       []model.SystemChange       `json:"changes,omitempty"`
	FleetPeers    string                     `json:"fleet_peers,omitempty"` // human-readable peer correlation summary

	// Gate audit — why the verdict landed where it did.
	GateAudit traceGateAudit `json:"gate_audit"`

	// Lifecycle.
	Incident *RCAIncident `json:"incident,omitempty"`

	// Final verdict.
	Verdict traceVerdict `json:"verdict"`
}

type traceInputs struct {
	CPUBusyPct       float64 `json:"cpu_busy_pct"`
	CPUIOWaitPct     float64 `json:"cpu_iowait_pct"`
	CPUStealPct      float64 `json:"cpu_steal_pct"`
	LoadAvg1         float64 `json:"loadavg_1"`
	NumCPUs          int     `json:"num_cpus"`
	PSICPUSomeAvg10  float64 `json:"psi_cpu_some_avg10"`
	PSIMemSomeAvg10  float64 `json:"psi_mem_some_avg10"`
	PSIIOSomeAvg10   float64 `json:"psi_io_some_avg10"`
	PSIIOFullAvg10   float64 `json:"psi_io_full_avg10"`
	MemTotalGB       float64 `json:"mem_total_gb"`
	MemAvailablePct  float64 `json:"mem_available_pct"`
	SwapInRate       float64 `json:"swap_in_rate"`
	DirectReclaimRate float64 `json:"direct_reclaim_rate"`
	OOMKillDelta     uint64  `json:"oom_kill_delta"`
	NetRetransRate   float64 `json:"net_retrans_rate"`
	TCPResetRate     float64 `json:"tcp_reset_rate"`
	ConntrackPct     float64 `json:"conntrack_pct"`
}

type traceDomain struct {
	Bottleneck       string           `json:"bottleneck"`
	Score            int              `json:"score"`
	DomainConf       float64          `json:"domain_conf"`
	EvidenceFiring   []model.Evidence `json:"evidence_firing"`
	// EvidenceRejected lists checks the detector evaluated but that did not
	// fire (strength < evidenceStrengthMin). Audits "what did xtop check and
	// rule out?" — TODO #6.
	EvidenceRejected []model.Evidence `json:"evidence_rejected,omitempty"`
	TopProcess       string           `json:"top_process,omitempty"`
	TopPID           int              `json:"top_pid,omitempty"`
	TopCgroup        string           `json:"top_cgroup,omitempty"`
}

type traceGateAudit struct {
	V2TrustGatePassed         bool     `json:"v2_trust_gate_passed"`
	V2TrustGateFailReason     string   `json:"v2_trust_gate_fail_reason,omitempty"`
	ConfirmedTrustGatePassed  bool     `json:"confirmed_trust_gate_passed"`
	ConfirmedTrustGateReason  string   `json:"confirmed_trust_gate_reason,omitempty"`
	WeightCategoriesFiring    []string `json:"weight_categories_firing"`
	MaxSustainedForSec        float64  `json:"max_sustained_for_sec"`
	MinSustainedRequiredSec   float64  `json:"min_sustained_required_sec"`
	RunnerUpDomain            string   `json:"runner_up_domain,omitempty"`
	RunnerUpScore             int      `json:"runner_up_score"`
	ScoreGapToRunnerUp        int      `json:"score_gap_to_runner_up"`
}

type traceVerdict struct {
	Health            string `json:"health"`
	Confidence        int    `json:"confidence"`
	PrimaryBottleneck string `json:"primary_bottleneck"`
	PrimaryScore      int    `json:"primary_score"`
	PrimaryProcess    string `json:"primary_process,omitempty"`
	PrimaryAppName    string `json:"primary_app_name,omitempty"`
}

// write builds + writes both .json and .md files. Best-effort: I/O errors are
// logged via stderr but never abort the engine.
func (t *TraceArmer) write(
	snap *model.Snapshot,
	rates *model.RateSnapshot,
	result *model.AnalysisResult,
	hist *History,
	active *RCAIncident,
) {
	tf := buildTraceFile(snap, rates, result, hist, active)

	if err := os.MkdirAll(t.dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "xtop trace: mkdir %s: %v\n", t.dir, err)
		return
	}
	stamp := tf.WrittenAt.Unix()
	jsonPath := filepath.Join(t.dir, fmt.Sprintf("trace-%d.json", stamp))
	mdPath := filepath.Join(t.dir, fmt.Sprintf("trace-%d.md", stamp))

	if data, err := json.MarshalIndent(tf, "", "  "); err == nil {
		if err := os.WriteFile(jsonPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "xtop trace: write %s: %v\n", jsonPath, err)
		}
	}
	if err := os.WriteFile(mdPath, []byte(renderTraceMarkdown(&tf)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "xtop trace: write %s: %v\n", mdPath, err)
	}
	fmt.Fprintf(os.Stderr, "xtop trace: wrote %s and %s\n", jsonPath, mdPath)
}

func buildTraceFile(
	snap *model.Snapshot,
	rates *model.RateSnapshot,
	result *model.AnalysisResult,
	hist *History,
	active *RCAIncident,
) TraceFile {
	host := ""
	if snap != nil && snap.SysInfo != nil {
		host = snap.SysInfo.Hostname
	}

	tf := TraceFile{
		Schema:    "xtop.trace.v1",
		WrittenAt: time.Now(),
		Hostname:  host,
	}

	if snap != nil {
		tf.Inputs.PSICPUSomeAvg10 = snap.Global.PSI.CPU.Some.Avg10
		tf.Inputs.PSIMemSomeAvg10 = snap.Global.PSI.Memory.Some.Avg10
		tf.Inputs.PSIIOSomeAvg10 = snap.Global.PSI.IO.Some.Avg10
		tf.Inputs.PSIIOFullAvg10 = snap.Global.PSI.IO.Full.Avg10
		tf.Inputs.NumCPUs = snap.Global.CPU.NumCPUs
		tf.Inputs.LoadAvg1 = snap.Global.CPU.LoadAvg.Load1
		if snap.Global.Memory.Total > 0 {
			tf.Inputs.MemTotalGB = float64(snap.Global.Memory.Total) / (1024 * 1024 * 1024)
			tf.Inputs.MemAvailablePct = float64(snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
		}
		if snap.Global.Conntrack.Max > 0 {
			tf.Inputs.ConntrackPct = float64(snap.Global.Conntrack.Count) / float64(snap.Global.Conntrack.Max) * 100
		}
	}
	if rates != nil {
		tf.Inputs.CPUBusyPct = rates.CPUBusyPct
		tf.Inputs.CPUIOWaitPct = rates.CPUIOWaitPct
		tf.Inputs.SwapInRate = rates.SwapInRate
		tf.Inputs.DirectReclaimRate = rates.DirectReclaimRate
		tf.Inputs.OOMKillDelta = rates.OOMKillDelta
		tf.Inputs.NetRetransRate = rates.RetransRate
		tf.Inputs.TCPResetRate = rates.TCPResetRate
	}

	for _, e := range result.RCA {
		var firing, rejected []model.Evidence
		for _, ev := range e.EvidenceV2 {
			if ev.Strength >= evidenceStrengthMin {
				firing = append(firing, ev)
			} else if ev.ID != "" {
				rejected = append(rejected, ev)
			}
		}
		tf.Domains = append(tf.Domains, traceDomain{
			Bottleneck:       e.Bottleneck,
			Score:            e.Score,
			DomainConf:       e.DomainConf,
			EvidenceFiring:   firing,
			EvidenceRejected: rejected,
			TopProcess:       e.TopProcess,
			TopPID:           e.TopPID,
			TopCgroup:        e.TopCgroup,
		})
	}

	tf.Correlations = result.Correlations
	tf.Blame = result.Blame
	tf.CausalChain = result.CausalChain
	tf.AppAnomalies = result.AppAnomalies
	tf.DriftWarnings = result.Degradations
	tf.Probes = result.ProbeResults
	tf.Changes = result.Changes
	tf.FleetPeers = result.CrossHostCorrelation

	tf.GateAudit = buildGateAudit(result)
	tf.Incident = active

	tf.Verdict = traceVerdict{
		Health:            result.Health.String(),
		Confidence:        result.Confidence,
		PrimaryBottleneck: result.PrimaryBottleneck,
		PrimaryScore:      result.PrimaryScore,
		PrimaryProcess:    result.PrimaryProcess,
		PrimaryAppName:    result.PrimaryAppName,
	}
	return tf
}

func buildGateAudit(result *model.AnalysisResult) traceGateAudit {
	audit := traceGateAudit{
		MinSustainedRequiredSec: minSustainedSec,
	}
	if len(result.RCA) == 0 {
		return audit
	}

	var primary model.RCAEntry
	for _, e := range result.RCA {
		if e.Bottleneck == result.PrimaryBottleneck {
			primary = e
			break
		}
	}

	audit.V2TrustGatePassed = v2TrustGate(primary.EvidenceV2)
	audit.ConfirmedTrustGatePassed = confirmedTrustGate(primary.EvidenceV2)

	cats := make(map[string]bool)
	for _, ev := range primary.EvidenceV2 {
		if ev.Strength < evidenceStrengthMin {
			continue
		}
		cat := ev.Tags["weight"]
		if cat == "" {
			cat = "secondary"
		}
		cats[cat] = true
		if ev.SustainedForSec > audit.MaxSustainedForSec {
			audit.MaxSustainedForSec = ev.SustainedForSec
		}
	}
	for c := range cats {
		audit.WeightCategoriesFiring = append(audit.WeightCategoriesFiring, c)
	}

	if !audit.V2TrustGatePassed {
		switch {
		case evidenceGroupsFired(primary.EvidenceV2, evidenceStrengthMin) < 2:
			audit.V2TrustGateFailReason = "fewer than 2 evidence groups firing"
		case !hasMeasuredHighConf(primary.EvidenceV2, evidenceStrengthMin, 0.8):
			audit.V2TrustGateFailReason = "no measured evidence with confidence >= 0.8"
		case len(cats) < 2:
			audit.V2TrustGateFailReason = "evidence spans only one weight category (no diversity)"
		}
	}
	if audit.V2TrustGatePassed && !audit.ConfirmedTrustGatePassed {
		audit.ConfirmedTrustGateReason = fmt.Sprintf(
			"max sustained=%.1fs, required=%.1fs", audit.MaxSustainedForSec, minSustainedSec,
		)
	} else if audit.ConfirmedTrustGatePassed {
		audit.ConfirmedTrustGateReason = "passed"
	}

	if len(result.RCA) >= 2 {
		audit.RunnerUpDomain = result.RCA[1].Bottleneck
		audit.RunnerUpScore = result.RCA[1].Score
		audit.ScoreGapToRunnerUp = result.RCA[0].Score - result.RCA[1].Score
	}
	return audit
}

func renderTraceMarkdown(tf *TraceFile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# xtop RCA trace — %s\n\n", tf.WrittenAt.Format(time.RFC3339))
	if tf.Hostname != "" {
		fmt.Fprintf(&b, "Host: `%s`\n\n", tf.Hostname)
	}

	fmt.Fprintf(&b, "## Verdict\n\n")
	fmt.Fprintf(&b, "- **Health:** %s (confidence %d)\n", tf.Verdict.Health, tf.Verdict.Confidence)
	fmt.Fprintf(&b, "- **Primary bottleneck:** %s (score %d)\n", tf.Verdict.PrimaryBottleneck, tf.Verdict.PrimaryScore)
	if tf.Verdict.PrimaryProcess != "" {
		fmt.Fprintf(&b, "- **Top culprit:** %s", tf.Verdict.PrimaryProcess)
		if tf.Verdict.PrimaryAppName != "" {
			fmt.Fprintf(&b, " (app: %s)", tf.Verdict.PrimaryAppName)
		}
		b.WriteString("\n")
	}
	if tf.Incident != nil {
		fmt.Fprintf(&b, "- **Incident state:** %s", tf.Incident.State)
		if !tf.Incident.ConfirmedAt.IsZero() {
			fmt.Fprintf(&b, " (confirmed at %s)", tf.Incident.ConfirmedAt.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "## Inputs (what xtop measured)\n\n")
	fmt.Fprintf(&b, "| Signal | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| CPU busy %% | %.1f |\n", tf.Inputs.CPUBusyPct)
	fmt.Fprintf(&b, "| CPU iowait %% | %.1f |\n", tf.Inputs.CPUIOWaitPct)
	fmt.Fprintf(&b, "| Load avg (1m) | %.2f (across %d CPUs) |\n", tf.Inputs.LoadAvg1, tf.Inputs.NumCPUs)
	fmt.Fprintf(&b, "| PSI cpu some/10 | %.2f |\n", tf.Inputs.PSICPUSomeAvg10)
	fmt.Fprintf(&b, "| PSI mem some/10 | %.2f |\n", tf.Inputs.PSIMemSomeAvg10)
	fmt.Fprintf(&b, "| PSI io some/10 | %.2f |\n", tf.Inputs.PSIIOSomeAvg10)
	fmt.Fprintf(&b, "| PSI io full/10 | %.2f |\n", tf.Inputs.PSIIOFullAvg10)
	fmt.Fprintf(&b, "| Mem total / available%% | %.1f GB / %.1f%% |\n", tf.Inputs.MemTotalGB, tf.Inputs.MemAvailablePct)
	fmt.Fprintf(&b, "| Swap in / direct reclaim | %.2f / %.2f /s |\n", tf.Inputs.SwapInRate, tf.Inputs.DirectReclaimRate)
	fmt.Fprintf(&b, "| OOM kills (delta) | %d |\n", tf.Inputs.OOMKillDelta)
	fmt.Fprintf(&b, "| TCP retrans / reset | %.2f / %.2f /s |\n", tf.Inputs.NetRetransRate, tf.Inputs.TCPResetRate)
	fmt.Fprintf(&b, "| Conntrack %% | %.1f |\n\n", tf.Inputs.ConntrackPct)

	fmt.Fprintf(&b, "## Per-domain analysis\n\n")
	for _, d := range tf.Domains {
		fmt.Fprintf(&b, "### %s — score %d (conf %.2f)\n\n", d.Bottleneck, d.Score, d.DomainConf)
		if d.TopProcess != "" {
			fmt.Fprintf(&b, "Top process: `%s` (pid %d)  cgroup: `%s`\n\n", d.TopProcess, d.TopPID, d.TopCgroup)
		}
		if len(d.EvidenceFiring) == 0 {
			fmt.Fprintf(&b, "_No evidence firing._\n\n")
			continue
		}
		fmt.Fprintf(&b, "| Evidence | Strength | Conf | Sustained | Value | Threshold | Measured | Tag |\n")
		fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|\n")
		for _, e := range d.EvidenceFiring {
			fmt.Fprintf(&b, "| `%s` | %.2f | %.2f | %.1fs | %.2f | %.2f | %v | %s |\n",
				e.ID, e.Strength, e.Confidence, e.SustainedForSec, e.Value, e.Threshold, e.Measured, e.Tags["weight"])
		}
		if len(d.EvidenceRejected) > 0 {
			fmt.Fprintf(&b, "\n_Considered but not firing (value below threshold):_\n\n")
			fmt.Fprintf(&b, "| Evidence | Strength | Value | Threshold |\n|---|---|---|---|\n")
			for _, e := range d.EvidenceRejected {
				fmt.Fprintf(&b, "| `%s` | %.2f | %.2f | %.2f |\n",
					e.ID, e.Strength, e.Value, e.Threshold)
			}
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Gate audit (the why)\n\n")
	a := tf.GateAudit
	fmt.Fprintf(&b, "- v2 trust gate: **%s**", okFail(a.V2TrustGatePassed))
	if a.V2TrustGateFailReason != "" {
		fmt.Fprintf(&b, " — %s", a.V2TrustGateFailReason)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- confirmed trust gate (sustained): **%s**", okFail(a.ConfirmedTrustGatePassed))
	if a.ConfirmedTrustGateReason != "" {
		fmt.Fprintf(&b, " — %s", a.ConfirmedTrustGateReason)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "- weight categories firing: %s\n", strings.Join(a.WeightCategoriesFiring, ", "))
	fmt.Fprintf(&b, "- max sustained: %.1fs (required for confirm: %.1fs)\n", a.MaxSustainedForSec, a.MinSustainedRequiredSec)
	if a.RunnerUpDomain != "" {
		fmt.Fprintf(&b, "- runner-up: %s (score %d, gap %d)\n", a.RunnerUpDomain, a.RunnerUpScore, a.ScoreGapToRunnerUp)
	}
	b.WriteString("\n")

	if len(tf.Correlations) > 0 {
		fmt.Fprintf(&b, "## Correlations\n\n")
		for _, c := range tf.Correlations {
			fmt.Fprintf(&b, "- `%s` ↔ `%s`: r=%.2f (%s, n=%d)\n", c.MetricA, c.MetricB, c.Coefficient, c.Strength, c.Samples)
		}
		b.WriteString("\n")
	}
	if len(tf.Blame) > 0 {
		fmt.Fprintf(&b, "## Blame attribution\n\n")
		for _, e := range tf.Blame {
			fmt.Fprintf(&b, "- pid %d `%s` (impact %.1f%%)", e.PID, e.Comm, e.ImpactPct)
			if e.AppName != "" {
				fmt.Fprintf(&b, " app=%s", e.AppName)
			}
			if e.CgroupPath != "" {
				fmt.Fprintf(&b, " cgroup=%s", e.CgroupPath)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(tf.AppAnomalies) > 0 {
		fmt.Fprintf(&b, "## Per-app baseline anomalies\n\n")
		fmt.Fprintf(&b, "| App | Metric | Current | Hour-of-week mean ± std | σ | Note |\n")
		fmt.Fprintf(&b, "|---|---|---|---|---|---|\n")
		for _, a := range tf.AppAnomalies {
			fmt.Fprintf(&b, "| `%s` | %s | %.2f | %.2f ± %.2f | %.2f | %s |\n",
				a.AppName, a.Metric, a.Current, a.HourBaseline, a.HourStdDev, a.Sigma, a.Note)
		}
		b.WriteString("\n")
	}
	if len(tf.DriftWarnings) > 0 {
		fmt.Fprintf(&b, "## Slow-drift warnings (boiling frog)\n\n")
		for _, d := range tf.DriftWarnings {
			fmt.Fprintf(&b, "- `%s` %s for %ds at %.2f %s\n", d.Metric, d.Direction, d.Duration, d.Rate, d.Unit)
		}
		b.WriteString("\n")
	}
	if len(tf.Changes) > 0 {
		fmt.Fprintf(&b, "## Recent system changes\n\n")
		for _, c := range tf.Changes {
			fmt.Fprintf(&b, "- [%s] %s — %s\n", c.When.Format("15:04:05"), c.Type, c.Detail)
		}
		b.WriteString("\n")
	}
	if tf.FleetPeers != "" {
		fmt.Fprintf(&b, "## Fleet peers\n\n%s\n\n", tf.FleetPeers)
	}
	if len(tf.Probes) > 0 {
		fmt.Fprintf(&b, "## Active probes (Phase 6)\n\n")
		fmt.Fprintf(&b, "%s\n", SummarizeForTrace(tf.Probes))
		for _, p := range tf.Probes {
			fmt.Fprintf(&b, "### %s (trigger=`%s`)\n\n", p.Name, p.EvidenceID)
			out := p.Output
			if len(out) > 4096 {
				out = out[:4096] + "\n…[truncated for markdown]"
			}
			fmt.Fprintf(&b, "```\n%s\n```\n\n", out)
			if p.Truncated {
				b.WriteString("_(probe stdout was truncated at 64 KB)_\n\n")
			}
		}
	}
	if tf.CausalChain != "" {
		fmt.Fprintf(&b, "## Causal chain\n\n%s\n", tf.CausalChain)
	}
	return b.String()
}

func okFail(b bool) string {
	if b {
		return "PASS"
	}
	return "FAIL"
}
