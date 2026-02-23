package collector

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ftahirops/xtop/model"
)

// #3: Shared HTTP client with proper transport reuse
var sharedHTTPClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:      20,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// HealthCheckCollector performs active health probes against discovered services.
type HealthCheckCollector struct {
	mu            sync.Mutex
	cached        []model.HealthProbeResult
	lastProbe     time.Time
	lastCertScan  time.Time
	lastDiscover  time.Time // #25: re-discover periodically
	targets       []probeTarget
	discovered    bool
}

type probeTarget struct {
	name      string
	probeType string // "http", "tcp", "dns", "cert"
	target    string // URL, host:port, or domain
}

func (h *HealthCheckCollector) Name() string { return "healthcheck" }

func (h *HealthCheckCollector) Collect(snap *model.Snapshot) error {
	h.mu.Lock()

	if !h.discovered {
		h.discoverTargets(snap)
		h.discovered = true
		h.lastDiscover = time.Now()
	}

	// #25: Re-discover targets every 5 minutes
	if time.Since(h.lastDiscover) >= 5*time.Minute {
		h.discoverTargets(snap)
		h.lastDiscover = time.Now()
	}

	now := time.Now()
	needProbe := now.Sub(h.lastProbe) >= 10*time.Second
	needCert := now.Sub(h.lastCertScan) >= 5*time.Minute

	// Copy targets to run probes outside the lock (#6)
	var targetsCopy []probeTarget
	if needProbe {
		targetsCopy = make([]probeTarget, len(h.targets))
		copy(targetsCopy, h.targets)
	}
	h.mu.Unlock()

	// #6: Run probes OUTSIDE the mutex to avoid blocking
	if needProbe {
		results := runProbesUnlocked(targetsCopy)

		h.mu.Lock()
		// Merge with existing cert-file results
		var merged []model.HealthProbeResult
		merged = append(merged, results...)
		for _, c := range h.cached {
			if c.ProbeType == "cert" {
				merged = append(merged, c)
			}
		}
		h.cached = merged
		h.lastProbe = now
		h.mu.Unlock()
	}

	if needCert {
		h.mu.Lock()
		h.scanCertFiles()
		h.lastCertScan = now
		h.mu.Unlock()
	}

	h.mu.Lock()
	snap.Global.HealthChecks.Probes = h.cached
	h.mu.Unlock()
	return nil
}

func (h *HealthCheckCollector) discoverTargets(snap *model.Snapshot) {
	h.targets = nil

	// Known service ports → TCP probes
	knownPorts := map[int]string{
		5432:  "PostgreSQL",
		3306:  "MySQL",
		6379:  "Redis",
		27017: "MongoDB",
		9200:  "Elasticsearch",
		5672:  "RabbitMQ",
		11211: "Memcached",
	}

	listenPorts := getListenPorts()
	seen := make(map[int]bool)
	for _, lp := range listenPorts {
		if seen[lp.port] {
			continue
		}
		seen[lp.port] = true

		if name, ok := knownPorts[lp.port]; ok {
			h.targets = append(h.targets, probeTarget{
				name:      name,
				probeType: "tcp",
				target:    fmt.Sprintf("127.0.0.1:%d", lp.port),
			})
		}

		// HTTP probes for well-known web ports
		if lp.port == 80 {
			h.targets = append(h.targets, probeTarget{
				name:      "HTTP",
				probeType: "http",
				target:    "http://127.0.0.1:80/",
			})
		}
		if lp.port == 443 {
			h.targets = append(h.targets, probeTarget{
				name:      "HTTPS",
				probeType: "http",
				target:    "https://127.0.0.1:443/",
			})
		}
		if lp.port == 8080 {
			h.targets = append(h.targets, probeTarget{
				name:      "HTTP-Alt",
				probeType: "http",
				target:    "http://127.0.0.1:8080/",
			})
		}
		if lp.port == 8443 {
			h.targets = append(h.targets, probeTarget{
				name:      "HTTPS-Alt",
				probeType: "http",
				target:    "https://127.0.0.1:8443/",
			})
		}
	}
}

// runProbesUnlocked runs probes without holding any mutex (#6).
func runProbesUnlocked(targets []probeTarget) []model.HealthProbeResult {
	results := make([]model.HealthProbeResult, len(targets))

	sem := make(chan struct{}, 5) // max 5 concurrent
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target probeTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var r model.HealthProbeResult
			switch target.probeType {
			case "http":
				r = probeHTTP(target)
			case "tcp":
				r = probeTCP(target)
			case "dns":
				r = probeDNS(target)
			default:
				r = model.HealthProbeResult{
					Name:         target.name,
					ProbeType:    target.probeType,
					Target:       target.target,
					Status:       "UNKNOWN",
					CertDaysLeft: -1,
				}
			}
			r.LastCheck = time.Now()
			results[idx] = r
		}(i, t)
	}
	wg.Wait()
	return results
}

func probeHTTP(t probeTarget) model.HealthProbeResult {
	r := model.HealthProbeResult{
		Name:         t.name,
		ProbeType:    "http",
		Target:       t.target,
		CertDaysLeft: -1,
	}

	// #3: Use shared HTTP client instead of creating new one per call
	start := time.Now()
	resp, err := sharedHTTPClient.Get(t.target)
	r.LatencyMs = float64(time.Since(start).Microseconds()) / 1000

	if err != nil {
		r.Status = "CRIT"
		r.Detail = truncateStr(err.Error(), 60)
		return r
	}
	defer resp.Body.Close()

	r.StatusCode = resp.StatusCode
	if resp.StatusCode >= 500 {
		r.Status = "CRIT"
		r.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else if resp.StatusCode >= 400 {
		r.Status = "WARN"
		r.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	} else {
		r.Status = "OK"
		r.Detail = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	// Extract cert expiry for HTTPS
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		r.CertDaysLeft = daysLeft
		if daysLeft < 7 {
			r.Status = "CRIT"
			r.Detail += fmt.Sprintf(" (cert expires in %dd)", daysLeft)
		} else if daysLeft < 30 {
			if r.Status == "OK" {
				r.Status = "WARN"
			}
			r.Detail += fmt.Sprintf(" (cert expires in %dd)", daysLeft)
		}
	}

	return r
}

func probeTCP(t probeTarget) model.HealthProbeResult {
	r := model.HealthProbeResult{
		Name:         t.name,
		ProbeType:    "tcp",
		Target:       t.target,
		CertDaysLeft: -1,
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", t.target, 3*time.Second)
	r.LatencyMs = float64(time.Since(start).Microseconds()) / 1000

	if err != nil {
		r.Status = "CRIT"
		r.Detail = "Connection refused"
		return r
	}
	conn.Close()

	r.Status = "OK"
	r.Detail = fmt.Sprintf("Connected in %.0fms", r.LatencyMs)
	return r
}

func probeDNS(t probeTarget) model.HealthProbeResult {
	r := model.HealthProbeResult{
		Name:         t.name,
		ProbeType:    "dns",
		Target:       t.target,
		CertDaysLeft: -1,
	}

	start := time.Now()
	addrs, err := net.LookupHost(t.target)
	r.LatencyMs = float64(time.Since(start).Microseconds()) / 1000

	if err != nil {
		r.Status = "CRIT"
		r.Detail = "DNS resolution failed"
		return r
	}

	r.Status = "OK"
	if len(addrs) > 0 {
		r.Detail = addrs[0]
	}
	return r
}

func (h *HealthCheckCollector) scanCertFiles() {
	// Remove old cert-file results
	var remaining []model.HealthProbeResult
	for _, r := range h.cached {
		if r.ProbeType != "cert" {
			remaining = append(remaining, r)
		}
	}

	// Scan /etc/letsencrypt/live/*/cert.pem
	matches, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem")
	for _, certPath := range matches {
		data, err := os.ReadFile(certPath)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		domain := cert.Subject.CommonName
		if domain == "" && len(cert.DNSNames) > 0 {
			domain = cert.DNSNames[0]
		}

		status := "OK"
		detail := fmt.Sprintf("Expires %s", cert.NotAfter.Format("2006-01-02"))
		if daysLeft < 7 {
			status = "CRIT"
		} else if daysLeft < 30 {
			status = "WARN"
		}

		remaining = append(remaining, model.HealthProbeResult{
			Name:         domain,
			ProbeType:    "cert",
			Target:       certPath,
			Status:       status,
			Detail:       detail,
			CertDaysLeft: daysLeft,
			LastCheck:    time.Now(),
		})
	}

	h.cached = remaining
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
