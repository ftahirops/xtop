package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/store"
)

// SnapshotProvider gives access to the latest snapshot data.
type SnapshotProvider interface {
	Latest() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult)
	ImpactScores() []model.ImpactScore
}

// Server is a Unix socket HTTP API server for xtop.
type Server struct {
	sockPath string
	listener net.Listener
	mux      *http.ServeMux
	provider SnapshotProvider
	store    *store.Store
}

// NewServer creates a new API server.
// sockPath: path to Unix socket (/run/xtop.sock or ~/.xtop/xtop.sock).
func NewServer(sockPath string, provider SnapshotProvider, st *store.Store) (*Server, error) {
	// Clean up stale socket
	if _, err := os.Stat(sockPath); err == nil {
		os.Remove(sockPath)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(sockPath), 0700); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", sockPath, err)
	}

	// Set socket permissions to owner-only
	os.Chmod(sockPath, 0600)

	s := &Server{
		sockPath: sockPath,
		listener: ln,
		mux:      http.NewServeMux(),
		provider: provider,
		store:    st,
	}

	s.mux.HandleFunc("/v1/status", s.handleStatus)
	s.mux.HandleFunc("/v1/top", s.handleTop)
	s.mux.HandleFunc("/v1/proc/", s.handleProc)
	s.mux.HandleFunc("/v1/incidents", s.handleIncidents)
	s.mux.HandleFunc("/v1/incident/", s.handleIncident)

	return s, nil
}

// Serve starts accepting connections. Blocks until error or Close().
func (s *Server) Serve() error {
	srv := &http.Server{Handler: s.mux}
	return srv.Serve(s.listener)
}

// Close closes the listener and removes the socket file.
func (s *Server) Close() error {
	err := s.listener.Close()
	os.Remove(s.sockPath)
	return err
}

// SockPath returns the socket path.
func (s *Server) SockPath() string { return s.sockPath }

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap, rates, result := s.provider.Latest()
	if snap == nil || result == nil {
		http.Error(w, "no data", http.StatusServiceUnavailable)
		return
	}

	resp := StatusResponse{
		Timestamp:  snap.Timestamp,
		Health:     result.Health.String(),
		Confidence: result.Confidence,
		Bottleneck: result.PrimaryBottleneck,
		Score:      result.PrimaryScore,
	}
	if result.Narrative != nil {
		resp.RootCause = result.Narrative.RootCause
		resp.Pattern = result.Narrative.Pattern
	}
	if result.CausalChain != "" {
		resp.CausalChain = result.CausalChain
	}
	if len(result.Blame) > 0 {
		resp.TopOffender = result.Blame[0].Comm
		resp.TopOffenderPID = result.Blame[0].PID
	}
	resp.CPUBusy = 0
	if rates != nil {
		resp.CPUBusy = rates.CPUBusyPct
	}
	if snap.Global.Memory.Total > 0 {
		resp.MemPct = float64(snap.Global.Memory.Total-snap.Global.Memory.Available) / float64(snap.Global.Memory.Total) * 100
	}

	writeJSON(w, resp)
}

func (s *Server) handleTop(w http.ResponseWriter, r *http.Request) {
	scores := s.provider.ImpactScores()
	if len(scores) == 0 {
		writeJSON(w, []model.ImpactScore{})
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if len(scores) > limit {
		scores = scores[:limit]
	}
	writeJSON(w, scores)
}

func (s *Server) handleProc(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/proc/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "pid required", http.StatusBadRequest)
		return
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, "invalid pid", http.StatusBadRequest)
		return
	}

	// Find process in current impact scores
	scores := s.provider.ImpactScores()
	for _, sc := range scores {
		if sc.PID == pid {
			writeJSON(w, sc)
			return
		}
	}
	http.Error(w, fmt.Sprintf("pid %d not found", pid), http.StatusNotFound)
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "no store", http.StatusServiceUnavailable)
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	records, err := s.store.ListIncidents(limit, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, records)
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "no store", http.StatusServiceUnavailable)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/v1/incident/")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	rec, err := s.store.GetIncident(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	offenders, _ := s.store.GetOffenders(id)

	writeJSON(w, map[string]interface{}{
		"incident":  rec,
		"offenders": offenders,
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// StatusResponse is the /v1/status endpoint response.
type StatusResponse struct {
	Timestamp      interface{} `json:"timestamp"`
	Health         string      `json:"health"`
	Confidence     int         `json:"confidence"`
	Bottleneck     string      `json:"bottleneck,omitempty"`
	Score          int         `json:"score"`
	RootCause      string      `json:"root_cause,omitempty"`
	Pattern        string      `json:"pattern,omitempty"`
	CausalChain    string      `json:"causal_chain,omitempty"`
	TopOffender    string      `json:"top_offender,omitempty"`
	TopOffenderPID int         `json:"top_offender_pid,omitempty"`
	CPUBusy        float64     `json:"cpu_busy"`
	MemPct         float64     `json:"mem_pct"`
}

// DefaultSockPath returns the preferred socket path.
func DefaultSockPath() string {
	// Try /run first (requires root)
	if _, err := os.Stat("/run"); err == nil {
		if os.Geteuid() == 0 {
			return "/run/xtop.sock"
		}
	}
	// Fallback to user home
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/xtop.sock"
	}
	return filepath.Join(home, ".xtop", "xtop.sock")
}

// DaemonSnapshotProvider wraps engine state for the API.
type DaemonSnapshotProvider struct {
	mu     sync.RWMutex
	snap   *model.Snapshot
	rates  *model.RateSnapshot
	result *model.AnalysisResult
	scores []model.ImpactScore
}

func NewDaemonSnapshotProvider() *DaemonSnapshotProvider {
	return &DaemonSnapshotProvider{}
}

func (p *DaemonSnapshotProvider) Update(snap *model.Snapshot, rates *model.RateSnapshot, result *model.AnalysisResult, scores []model.ImpactScore) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.snap = snap
	p.rates = rates
	p.result = result
	p.scores = scores
}

func (p *DaemonSnapshotProvider) Latest() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.snap, p.rates, p.result
}

func (p *DaemonSnapshotProvider) ImpactScores() []model.ImpactScore {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.scores
}
