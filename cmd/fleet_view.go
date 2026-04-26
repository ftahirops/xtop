package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// runFleetView implements `xtop fleet` — a live TUI showing all hosts reporting
// to a hub. Streams events over SSE so the table updates the moment a remote
// agent ticks or opens an incident.
func runFleetView(args []string) error {
	fs := flag.NewFlagSet("fleet", flag.ExitOnError)
	var (
		hub      = fs.String("hub", "", "hub URL (default: $XTOP_FLEET_HUB or ~/.xtop/fleet.json)")
		token    = fs.String("token", "", "auth token")
		insecure = fs.Bool("insecure", true, "skip TLS verification (for self-signed certs)")
		once     = fs.Bool("once", false, "print current host list as JSON and exit")
		refresh  = fs.Duration("refresh", 1*time.Second, "screen refresh cadence")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `xtop fleet — live multi-host dashboard

Connects to an xtop hub and streams per-host health, bottleneck, and culprit
updates. Requires a hub started with 'xtop hub'.

Usage:
  xtop fleet --hub=https://hub:9200 --token=<TOKEN>
  xtop fleet --once                  # single JSON snapshot`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	home, _ := os.UserHomeDir()
	dataDir := fmt.Sprintf("%s/.xtop", home)
	cfg := loadFleetAgentConfig(dataDir)
	if *hub != "" {
		cfg.HubURL = *hub
	} else if cfg.HubURL == "" {
		cfg.HubURL = os.Getenv("XTOP_FLEET_HUB")
	}
	if *token != "" {
		cfg.Token = *token
	} else if cfg.Token == "" {
		cfg.Token = os.Getenv("XTOP_FLEET_TOKEN")
	}
	cfg.InsecureSkipVerify = *insecure

	if cfg.HubURL == "" {
		return errors.New("no hub URL set — pass --hub, set XTOP_FLEET_HUB, or put hub_url in ~/.xtop/fleet.json")
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
		},
	}

	if *once {
		hosts, err := fetchHosts(httpClient, cfg)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(hosts)
	}

	view := &fleetView{
		cfg:        cfg,
		httpClient: httpClient,
		hosts:      make(map[string]*model.FleetHost),
	}
	return view.Run(*refresh)
}

// ─── Standalone fleet TUI view (terminal polling, no bubbletea dep) ──────────

type fleetView struct {
	cfg        model.FleetAgentConfig
	httpClient *http.Client

	mu    sync.RWMutex
	hosts map[string]*model.FleetHost
	err   string
}

func (v *fleetView) Run(refresh time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial fetch
	if hosts, err := fetchHosts(v.httpClient, v.cfg); err == nil {
		v.mu.Lock()
		for _, h := range hosts {
			v.hosts[h.AgentID] = h
		}
		v.mu.Unlock()
	} else {
		v.setErr(err.Error())
	}

	// Stream in the background
	go v.streamLoop(ctx)

	// Render loop
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	fmt.Print("\x1b[?25l") // hide cursor
	defer fmt.Print("\x1b[?25h")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			v.render()
		}
	}
}

func (v *fleetView) setErr(s string) {
	v.mu.Lock()
	v.err = s
	v.mu.Unlock()
}

func (v *fleetView) streamLoop(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := v.stream(ctx); err != nil && ctx.Err() == nil {
			v.setErr(fmt.Sprintf("stream disconnected: %v (retrying in %s)", err, backoff))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		} else {
			backoff = 2 * time.Second
		}
	}
}

func (v *fleetView) stream(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.HubURL+model.FleetEndpointStream, nil)
	if err != nil {
		return err
	}
	if v.cfg.Token != "" {
		req.Header.Set(model.FleetAuthHeader, v.cfg.Token)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hub returned %d", resp.StatusCode)
	}
	v.setErr("")

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var curEvent, curData string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			curEvent = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			curData = strings.TrimPrefix(line, "data: ")
		case line == "":
			if curEvent != "" && curData != "" {
				v.handleEvent(curEvent, []byte(curData))
			}
			curEvent, curData = "", ""
		}
	}
	return sc.Err()
}

func (v *fleetView) handleEvent(event string, data []byte) {
	switch event {
	case "snapshot":
		var hosts []*model.FleetHost
		if err := json.Unmarshal(data, &hosts); err == nil {
			v.mu.Lock()
			v.hosts = make(map[string]*model.FleetHost, len(hosts))
			for _, h := range hosts {
				v.hosts[h.AgentID] = h
			}
			v.mu.Unlock()
		}
	case "heartbeat":
		var hb model.FleetHeartbeat
		if err := json.Unmarshal(data, &hb); err == nil {
			v.applyHeartbeat(&hb)
		}
	case "incident":
		// Incidents are reflected in the next heartbeat — nothing to do here yet.
	}
}

func (v *fleetView) applyHeartbeat(hb *model.FleetHeartbeat) {
	v.mu.Lock()
	defer v.mu.Unlock()
	h, ok := v.hosts[hb.AgentID]
	if !ok {
		h = &model.FleetHost{
			AgentID:   hb.AgentID,
			Hostname:  hb.Hostname,
			FirstSeen: hb.Timestamp,
		}
		v.hosts[hb.AgentID] = h
	}
	h.LastSeen = hb.Timestamp
	h.Hostname = hb.Hostname
	h.Tags = hb.Tags
	h.AgentVersion = hb.AgentVersion
	h.Health = hb.Health
	h.PrimaryBottleneck = hb.PrimaryBottleneck
	h.PrimaryScore = hb.PrimaryScore
	h.Confidence = hb.Confidence
	h.CulpritProcess = hb.CulpritProcess
	h.CulpritApp = hb.CulpritApp
	h.CPUBusyPct = hb.CPUBusyPct
	h.MemUsedPct = hb.MemUsedPct
	h.IOWorstUtil = hb.IOWorstUtil
	h.LoadAvg1 = hb.LoadAvg1
	h.NumCPUs = hb.NumCPUs
	h.ActiveIncidentID = hb.ActiveIncidentID
	h.Status = model.HostStatusLive
}

// ─── Rendering ───────────────────────────────────────────────────────────────

func (v *fleetView) render() {
	v.mu.RLock()
	hosts := make([]*model.FleetHost, 0, len(v.hosts))
	for _, h := range v.hosts {
		hosts = append(hosts, h)
	}
	errMsg := v.err
	v.mu.RUnlock()

	// Sort: unhealthy first, then by hostname.
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Health != hosts[j].Health {
			return hosts[i].Health > hosts[j].Health
		}
		return hosts[i].Hostname < hosts[j].Hostname
	})

	var sb strings.Builder
	sb.WriteString("\x1b[H\x1b[2J") // cursor home + clear screen
	sb.WriteString(B + "xtop fleet" + R + "  ")
	sb.WriteString(FCyn + v.cfg.HubURL + R + "  ")
	sb.WriteString(fmt.Sprintf("%s%d hosts%s\n", FBGrn, len(hosts), R))
	if errMsg != "" {
		sb.WriteString(FBRed + errMsg + R + "\n")
	}
	sb.WriteString("\n")

	headers := []string{"HOST", "HEALTH", "BOTTLENECK", "SCORE", "CPU%", "MEM%", "IO%", "LOAD", "CULPRIT", "LAST SEEN"}
	rows := make([][]string, 0, len(hosts))
	now := time.Now()
	for _, h := range hosts {
		status := lastSeenCell(now, h.LastSeen, h.Status)
		rows = append(rows, []string{
			h.Hostname,
			healthColor(h.Health),
			orDash(h.PrimaryBottleneck),
			scoreCell(h.PrimaryScore),
			pctCell(h.CPUBusyPct, 70, 90),
			pctCell(h.MemUsedPct, 80, 95),
			pctCell(h.IOWorstUtil, 60, 85),
			loadCell(h.LoadAvg1, h.NumCPUs),
			orDash(firstNonEmpty(h.CulpritApp, h.CulpritProcess)),
			status,
		})
	}
	if len(rows) == 0 {
		sb.WriteString(FBCyn + "  (no hosts have reported yet — waiting for heartbeats)\n" + R)
	} else {
		sb.WriteString(renderTable(headers, rows, nil))
	}
	sb.WriteString("\n" + "\033[2m" + "refreshing live • Ctrl-C to quit" + R + "\n")
	io.WriteString(os.Stdout, sb.String())
}

func orDash(s string) string {
	if s == "" {
		return "\033[2m" + "—" + R
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func scoreCell(n int) string {
	if n <= 0 {
		return "\033[2m" + "—" + R
	}
	switch {
	case n >= 80:
		return fmt.Sprintf("%s%s%d%s", B, FBRed, n, R)
	case n >= 50:
		return fmt.Sprintf("%s%d%s", FBYel, n, R)
	default:
		return fmt.Sprintf("%s%d%s", FBGrn, n, R)
	}
}

func pctCell(v, warn, crit float64) string {
	if v == 0 {
		return "\033[2m" + "  0" + R
	}
	return colorByThreshold(v, warn, crit)
}

func loadCell(l float64, cpus int) string {
	if cpus <= 0 {
		return fmt.Sprintf("%.1f", l)
	}
	ratio := l / float64(cpus)
	switch {
	case ratio >= 1.5:
		return fmt.Sprintf("%s%s%.1f%s", B, FBRed, l, R)
	case ratio >= 1.0:
		return fmt.Sprintf("%s%.1f%s", FBYel, l, R)
	default:
		return fmt.Sprintf("%s%.1f%s", FBGrn, l, R)
	}
}

func lastSeenCell(now, ts time.Time, status model.HostStatus) string {
	if ts.IsZero() {
		return "\033[2m" + "never" + R
	}
	age := now.Sub(ts)
	var label string
	switch {
	case age < 5*time.Second:
		label = "just now"
	case age < time.Minute:
		label = fmt.Sprintf("%ds ago", int(age.Seconds()))
	case age < time.Hour:
		label = fmt.Sprintf("%dm ago", int(age.Minutes()))
	default:
		label = fmt.Sprintf("%dh ago", int(age.Hours()))
	}
	switch status {
	case model.HostStatusExpired:
		return FBRed + label + R
	case model.HostStatusStale:
		return FBYel + label + R
	default:
		return FBGrn + label + R
	}
}

func fetchHosts(client *http.Client, cfg model.FleetAgentConfig) ([]*model.FleetHost, error) {
	req, err := http.NewRequest(http.MethodGet, cfg.HubURL+model.FleetEndpointHosts, nil)
	if err != nil {
		return nil, err
	}
	if cfg.Token != "" {
		req.Header.Set(model.FleetAuthHeader, cfg.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("hub returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out []*model.FleetHost
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parse hosts json: %w", err)
	}
	return out, nil
}
