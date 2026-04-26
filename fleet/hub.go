// Package fleet implements the xtop fleet hub — the central server that agents
// report to. It accepts heartbeats and incidents over HTTP(S), stores them in
// Postgres (primary) and SQLite (hot cache), and serves the UI (TUI + web).
package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"

	// Registers the "pgx" driver with database/sql
	_ "github.com/jackc/pgx/v5/stdlib"
	// Registers the "sqlite" driver with database/sql (CGO-free)
	_ "modernc.org/sqlite"
)

// Hub is the central aggregator server.
type Hub struct {
	cfg model.FleetHubConfig

	pg     *sql.DB // primary store, long-term history
	cache  *sql.DB // SQLite hot cache, last 1 hour in RAM/fast disk

	// In-memory registry keyed by agent_id for O(1) host status lookups.
	hostsMu sync.RWMutex
	hosts   map[string]*model.FleetHost

	// Subscribers to live events (for SSE). Each subscriber has a channel of
	// events it wants to receive. Buffered so slow clients can't block the hub.
	subsMu sync.Mutex
	subs   map[int]chan []byte
	subSeq int

	// Incident ingest dedupe — key is "agent|signature|update_type", value
	// is the last-seen timestamp. Short TTL (2 min) so memory stays
	// bounded without a background goroutine.
	dedupeMu sync.Mutex
	dedupe   map[string]time.Time

	// Tracks stale/expired hosts in background
	quitCh chan struct{}
	wg     sync.WaitGroup
}

// NewHub creates a new hub with the given configuration.
func NewHub(cfg model.FleetHubConfig) (*Hub, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf(":%d", model.FleetDefaultPort)
	}
	if cfg.IncidentRetentionDays == 0 {
		cfg.IncidentRetentionDays = 30
	}
	if cfg.HeartbeatRetentionHours == 0 {
		cfg.HeartbeatRetentionHours = 48
	}
	if cfg.SQLiteCachePath == "" {
		home, _ := os.UserHomeDir()
		cfg.SQLiteCachePath = filepath.Join(home, ".xtop", "hub-cache.sqlite")
	}
	_ = os.MkdirAll(filepath.Dir(cfg.SQLiteCachePath), 0o755)

	h := &Hub{
		cfg:    cfg,
		hosts:  make(map[string]*model.FleetHost),
		subs:   make(map[int]chan []byte),
		quitCh: make(chan struct{}),
	}

	// Open Postgres (required)
	if cfg.PostgresDSN == "" {
		return nil, errors.New("postgres_dsn is required in hub config")
	}
	pg, err := sql.Open("pgx", cfg.PostgresDSN)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	pg.SetMaxOpenConns(20)
	pg.SetMaxIdleConns(5)
	pg.SetConnMaxLifetime(30 * time.Minute)
	if err := pg.Ping(); err != nil {
		return nil, fmt.Errorf("postgres ping (dsn may be wrong or db down): %w", err)
	}
	h.pg = pg

	// Open SQLite cache (fast reads for TUI / web)
	cache, err := sql.Open("sqlite", cfg.SQLiteCachePath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("sqlite cache open: %w", err)
	}
	cache.SetMaxOpenConns(1) // SQLite likes single-writer
	h.cache = cache

	// Create schemas if needed
	if err := h.initPostgresSchema(); err != nil {
		return nil, fmt.Errorf("postgres schema init: %w", err)
	}
	if err := h.initCacheSchema(); err != nil {
		return nil, fmt.Errorf("sqlite cache schema init: %w", err)
	}

	// Background janitor for stale/expired hosts + retention pruning
	h.wg.Add(1)
	go h.janitor()

	return h, nil
}

// Start begins listening. Blocks until Stop is called or the listener errors.
func (h *Hub) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc(model.FleetEndpointHeartbeat, h.handleHeartbeat)
	mux.HandleFunc(model.FleetEndpointIncident, h.handleIncident)
	mux.HandleFunc(model.FleetEndpointHosts, h.handleListHosts)
	mux.HandleFunc(model.FleetEndpointHost, h.handleGetHost)
	mux.HandleFunc(model.FleetEndpointIncidents, h.handleListIncidents)
	mux.HandleFunc(model.FleetEndpointStream, h.handleStream)
	mux.HandleFunc("/health", h.handleHealth)
	// Web UI is registered here by RegisterWebUI() — see web.go.
	h.registerWebUI(mux)

	srv := &http.Server{
		Addr:              h.cfg.ListenAddr,
		Handler:           h.logMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second, // longer for SSE
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("xtop-hub listening on %s (token auth %s)", h.cfg.ListenAddr, h.authDescription())
	if h.cfg.TLSCert != "" && h.cfg.TLSKey != "" {
		return srv.ListenAndServeTLS(h.cfg.TLSCert, h.cfg.TLSKey)
	}
	return srv.ListenAndServe()
}

// Stop shuts down the hub.
func (h *Hub) Stop() {
	close(h.quitCh)
	h.wg.Wait()
	if h.pg != nil {
		_ = h.pg.Close()
	}
	if h.cache != nil {
		_ = h.cache.Close()
	}
}

// authDescription returns "enabled" or "disabled" for startup log.
func (h *Hub) authDescription() string {
	if h.cfg.AuthToken == "" {
		return "disabled (WARNING)"
	}
	return "enabled"
}

// ─── HTTP middleware ─────────────────────────────────────────────────────────

func (h *Hub) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		dur := time.Since(start)
		// Only log slow or error endpoints to avoid log flood from heartbeats.
		if dur > 100*time.Millisecond || strings.HasPrefix(r.URL.Path, "/v1/incident") {
			log.Printf("%s %s %dms", r.Method, r.URL.Path, dur.Milliseconds())
		}
	})
}

// requireAuth accepts the hub token from either the X-XTop-Token header
// (used by agents + CLI) or an "xtop_token" cookie (set by the web UI when
// the HTML is served). Anyone with HTTP access to the hub is already
// trusted in the current security model — the cookie just closes the
// browser-can't-add-headers gap for the JS dashboard without adding a
// second secret.
func (h *Hub) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if h.cfg.AuthToken == "" {
		return true
	}
	if tok := r.Header.Get(model.FleetAuthHeader); tok == h.cfg.AuthToken {
		return true
	}
	if c, err := r.Cookie(webTokenCookie); err == nil && c.Value == h.cfg.AuthToken {
		return true
	}
	http.Error(w, "invalid token", http.StatusUnauthorized)
	return false
}

// webTokenCookie is the cookie name the hub sets on its HTML index so the
// browser can authenticate follow-up XHR + EventSource requests without
// any JavaScript token-handling logic.
const webTokenCookie = "xtop_token"

// ─── Endpoints ───────────────────────────────────────────────────────────────

func (h *Hub) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"hosts": len(h.hosts),
	})
}

func (h *Hub) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	var hb model.FleetHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if hb.Hostname == "" || hb.AgentID == "" {
		http.Error(w, "hostname and agent_id required", http.StatusBadRequest)
		return
	}
	// Update in-memory registry
	h.updateHostFromHeartbeat(&hb)

	// Persist asynchronously — don't block the agent
	go h.persistHeartbeat(&hb)

	// Notify SSE subscribers
	h.broadcast("heartbeat", hb)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Hub) handleIncident(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !h.requireAuth(w, r) {
		return
	}
	var inc model.FleetIncident
	if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if inc.IncidentID == "" || inc.AgentID == "" {
		http.Error(w, "incident_id and agent_id required", http.StatusBadRequest)
		return
	}
	// Ingest quality gate — the agent-side gate in v0.43+ blocks these at
	// the source, but the hub enforces its own version in case an older
	// agent (or a misconfigured operator) pushes phantom incidents.
	//
	// Drop payloads that are all zeros AND not a Resolved close-out. A
	// Resolved event with peak=0/conf=0 is legitimate if the incident
	// opened with a higher peak — the Resolved itself never carries
	// updated scores, only the closing timestamp.
	if inc.UpdateType != model.IncidentResolved &&
		inc.PeakScore == 0 && inc.Confidence == 0 {
		w.WriteHeader(http.StatusNoContent) // silently drop
		return
	}
	// Per-(host, update_type, signature) rate limit — dedupe storms where
	// the same event repeats within 30s.
	if h.isDuplicateIncident(&inc) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	go h.persistIncident(&inc)
	h.broadcast("incident", inc)
	w.WriteHeader(http.StatusNoContent)
}

// isDuplicateIncident returns true when we've just seen the same (agent,
// signature, update_type) within the coalesce window. Rolling map with a
// 60-second TTL; zero persistence — survives just long enough to fold
// same-second escalation storms from an agent that's still on an old
// build.
func (h *Hub) isDuplicateIncident(inc *model.FleetIncident) bool {
	key := inc.AgentID + "|" + inc.Signature + "|" + string(inc.UpdateType)
	h.dedupeMu.Lock()
	defer h.dedupeMu.Unlock()
	now := time.Now()
	if h.dedupe == nil {
		h.dedupe = make(map[string]time.Time)
	}
	// Cheap GC: flush entries older than 2 minutes on every call. Keeps
	// the map bounded without a background goroutine.
	for k, t := range h.dedupe {
		if now.Sub(t) > 2*time.Minute {
			delete(h.dedupe, k)
		}
	}
	if last, ok := h.dedupe[key]; ok && now.Sub(last) < 30*time.Second {
		return true
	}
	h.dedupe[key] = now
	return false
}

func (h *Hub) handleListHosts(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	h.hostsMu.RLock()
	out := make([]*model.FleetHost, 0, len(h.hosts))
	for _, host := range h.hosts {
		cp := *host
		out = append(out, &cp)
	}
	h.hostsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (h *Hub) handleGetHost(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	hostname := strings.TrimPrefix(r.URL.Path, model.FleetEndpointHost)
	hostname = strings.Trim(hostname, "/")
	if hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}
	h.hostsMu.RLock()
	var found *model.FleetHost
	for _, host := range h.hosts {
		if host.Hostname == hostname {
			cp := *host
			found = &cp
			break
		}
	}
	h.hostsMu.RUnlock()
	if found == nil {
		http.Error(w, "host not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(found)
}

func (h *Hub) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	// Query params: ?host=foo  ?hours=24  ?limit=100
	q := r.URL.Query()
	hoursStr := q.Get("hours")
	hours := 24
	if hoursStr != "" {
		if n, err := parseInt(hoursStr); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	host := q.Get("host")
	limit := 100
	if ls := q.Get("limit"); ls != "" {
		if n, err := parseInt(ls); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	sinceCutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var rows *sql.Rows
	var err error
	if host != "" {
		rows, err = h.pg.QueryContext(ctx, `
			SELECT data FROM fleet_incidents
			WHERE hostname = $1 AND started_at >= $2
			ORDER BY started_at DESC LIMIT $3`, host, sinceCutoff, limit)
	} else {
		rows, err = h.pg.QueryContext(ctx, `
			SELECT data FROM fleet_incidents
			WHERE started_at >= $1
			ORDER BY started_at DESC LIMIT $2`, sinceCutoff, limit)
	}
	if err != nil {
		http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var out []model.FleetIncident
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var inc model.FleetIncident
		if err := json.Unmarshal(raw, &inc); err == nil {
			out = append(out, inc)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ─── SSE streaming ───────────────────────────────────────────────────────────

func (h *Hub) handleStream(w http.ResponseWriter, r *http.Request) {
	if !h.requireAuth(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := h.subscribe()
	defer h.unsubscribe(ch)

	// Initial snapshot so the UI has something immediately
	h.hostsMu.RLock()
	hosts := make([]*model.FleetHost, 0, len(h.hosts))
	for _, host := range h.hosts {
		cp := *host
		hosts = append(hosts, &cp)
	}
	h.hostsMu.RUnlock()
	if data, err := json.Marshal(hosts); err == nil {
		fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data)
		flusher.Flush()
	}

	// Keep-alive ticker
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_, _ = w.Write(ev)
			flusher.Flush()
		}
	}
}

func (h *Hub) subscribe() chan []byte {
	h.subsMu.Lock()
	defer h.subsMu.Unlock()
	h.subSeq++
	ch := make(chan []byte, 64)
	h.subs[h.subSeq] = ch
	return ch
}

func (h *Hub) unsubscribe(ch chan []byte) {
	h.subsMu.Lock()
	defer h.subsMu.Unlock()
	for id, c := range h.subs {
		if c == ch {
			delete(h.subs, id)
			close(c)
			return
		}
	}
}

func (h *Hub) broadcast(event string, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", event, data))

	h.subsMu.Lock()
	defer h.subsMu.Unlock()
	for id, ch := range h.subs {
		select {
		case ch <- msg:
		default:
			// Slow subscriber — drop it
			delete(h.subs, id)
			close(ch)
		}
	}
}

// ─── Host registry ───────────────────────────────────────────────────────────

func (h *Hub) updateHostFromHeartbeat(hb *model.FleetHeartbeat) {
	h.hostsMu.Lock()
	defer h.hostsMu.Unlock()
	existing := h.hosts[hb.AgentID]
	now := hb.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	if existing == nil {
		h.hosts[hb.AgentID] = &model.FleetHost{
			Hostname:          hb.Hostname,
			AgentID:           hb.AgentID,
			Tags:              hb.Tags,
			AgentVersion:      hb.AgentVersion,
			Kernel:            hb.Kernel,
			OS:                hb.OS,
			FirstSeen:         now,
			LastSeen:          now,
			Status:            model.HostStatusLive,
			Health:            hb.Health,
			PrimaryBottleneck: hb.PrimaryBottleneck,
			PrimaryScore:      hb.PrimaryScore,
			Confidence:        hb.Confidence,
			CulpritProcess:    hb.CulpritProcess,
			CulpritApp:        hb.CulpritApp,
			CPUBusyPct:        hb.CPUBusyPct,
			MemUsedPct:        hb.MemUsedPct,
			IOWorstUtil:       hb.IOWorstUtil,
			LoadAvg1:          hb.LoadAvg1,
			NumCPUs:           hb.NumCPUs,
			ActiveIncidentID:  hb.ActiveIncidentID,
			XtopOwnCPUPct:     hb.XtopOwnCPUPct,
			XtopOwnRSSMB:      hb.XtopOwnRSSMB,
			XtopGuardLevel:    hb.XtopGuardLevel,
			XtopMode:          hb.XtopMode,
		}
		return
	}
	existing.LastSeen = now
	existing.Status = model.HostStatusLive
	existing.Hostname = hb.Hostname
	existing.Tags = hb.Tags
	existing.AgentVersion = hb.AgentVersion
	existing.Kernel = hb.Kernel
	existing.OS = hb.OS
	existing.Health = hb.Health
	existing.PrimaryBottleneck = hb.PrimaryBottleneck
	existing.PrimaryScore = hb.PrimaryScore
	existing.Confidence = hb.Confidence
	existing.CulpritProcess = hb.CulpritProcess
	existing.CulpritApp = hb.CulpritApp
	existing.CPUBusyPct = hb.CPUBusyPct
	existing.MemUsedPct = hb.MemUsedPct
	existing.IOWorstUtil = hb.IOWorstUtil
	existing.LoadAvg1 = hb.LoadAvg1
	existing.NumCPUs = hb.NumCPUs
	existing.ActiveIncidentID = hb.ActiveIncidentID
	existing.XtopOwnCPUPct = hb.XtopOwnCPUPct
	existing.XtopOwnRSSMB = hb.XtopOwnRSSMB
	existing.XtopGuardLevel = hb.XtopGuardLevel
	existing.XtopMode = hb.XtopMode
}

// ─── Background janitor ──────────────────────────────────────────────────────

func (h *Hub) janitor() {
	defer h.wg.Done()
	staleTick := time.NewTicker(10 * time.Second)
	pruneTick := time.NewTicker(1 * time.Hour)
	defer staleTick.Stop()
	defer pruneTick.Stop()

	for {
		select {
		case <-h.quitCh:
			return
		case <-staleTick.C:
			h.updateStaleStatus()
		case <-pruneTick.C:
			h.pruneOldRecords()
		}
	}
}

// updateStaleStatus walks the registry and marks hosts stale/expired based on
// time since last heartbeat. Expired hosts are dropped from memory (their data
// remains in Postgres).
func (h *Hub) updateStaleStatus() {
	now := time.Now()
	h.hostsMu.Lock()
	defer h.hostsMu.Unlock()
	var expired []string
	for id, host := range h.hosts {
		age := now.Sub(host.LastSeen)
		switch {
		case age > 10*time.Minute:
			expired = append(expired, id)
		case age > 15*time.Second:
			host.Status = model.HostStatusStale
		default:
			host.Status = model.HostStatusLive
		}
	}
	for _, id := range expired {
		delete(h.hosts, id)
	}
}

func (h *Hub) pruneOldRecords() {
	hbCutoff := time.Now().Add(-time.Duration(h.cfg.HeartbeatRetentionHours) * time.Hour)
	incCutoff := time.Now().Add(-time.Duration(h.cfg.IncidentRetentionDays) * 24 * time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := h.pg.ExecContext(ctx, `DELETE FROM fleet_heartbeats WHERE ts < $1`, hbCutoff); err != nil {
		log.Printf("hub: prune heartbeats: %v", err)
	}
	if _, err := h.pg.ExecContext(ctx, `DELETE FROM fleet_incidents WHERE started_at < $1`, incCutoff); err != nil {
		log.Printf("hub: prune incidents: %v", err)
	}

	// SQLite cache keeps only last 1h
	cacheCutoff := time.Now().Add(-1 * time.Hour)
	if _, err := h.cache.ExecContext(ctx, `DELETE FROM heartbeats WHERE ts < ?`, cacheCutoff.Unix()); err != nil {
		log.Printf("hub: prune sqlite cache: %v", err)
	}
}

// parseInt is a tiny helper to avoid importing strconv everywhere.
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
