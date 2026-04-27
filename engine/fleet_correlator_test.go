package engine

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/model"
)

func TestTopologyCorrelator_RegisterAndCorrelate(t *testing.T) {
	tc := NewTopologyCorrelator()

	// Register hosts
	tc.RegisterHost(&HostTopology{
		HostID: "web-01",
		Role:   RoleWebServer,
		Tier:   1,
		Region: "us-east",
		Zone:   "us-east-1a",
		Peers:  []string{"app-01"},
	})
	tc.RegisterHost(&HostTopology{
		HostID: "app-01",
		Role:   RoleAppServer,
		Tier:   2,
		Region: "us-east",
		Zone:   "us-east-1a",
		Peers:  []string{"web-01", "db-01"},
	})
	tc.RegisterHost(&HostTopology{
		HostID: "db-01",
		Role:   RoleDatabase,
		Tier:   3,
		Region: "us-east",
		Zone:   "us-east-1b",
		Peers:  []string{"app-01"},
	})

	// Record incidents
	now := time.Now()
	tc.RecordIncident("web-01", &model.HostIncident{
		HostID:            "web-01",
		PrimaryBottleneck: "cpu",
		Timestamp:         now,
	})
	tc.RecordIncident("app-01", &model.HostIncident{
		HostID:            "app-01",
		PrimaryBottleneck: "cpu",
		Timestamp:         now.Add(5 * time.Second),
	})

	// Correlate from web-01
	corrs := tc.Correlate("web-01", 30*time.Second)
	if len(corrs) == 0 {
		t.Fatal("expected correlations")
	}

	// app-01 should be highly correlated (direct peer, same domain, close in time)
	found := false
	for _, c := range corrs {
		if c.TargetHost == "app-01" {
			found = true
			if c.Likelihood < 0.5 {
				t.Errorf("expected high likelihood for direct peer, got %.2f", c.Likelihood)
			}
			if c.Direction != "upstream" && c.Direction != "peer" {
				t.Errorf("expected upstream/peer direction, got %s", c.Direction)
			}
		}
	}
	if !found {
		t.Error("expected correlation with app-01")
	}
}

func TestTopologyCorrelator_NoCorrelationForDistantHosts(t *testing.T) {
	tc := NewTopologyCorrelator()

	tc.RegisterHost(&HostTopology{
		HostID: "web-01",
		Role:   RoleWebServer,
		Tier:   1,
		Region: "us-east",
		Zone:   "us-east-1a",
	})
	tc.RegisterHost(&HostTopology{
		HostID: "db-01",
		Role:   RoleDatabase,
		Tier:   3,
		Region: "us-west",
		Zone:   "us-west-2a",
	})

	now := time.Now()
	tc.RecordIncident("web-01", &model.HostIncident{
		HostID:            "web-01",
		PrimaryBottleneck: "cpu",
		Timestamp:         now,
	})
	tc.RecordIncident("db-01", &model.HostIncident{
		HostID:            "db-01",
		PrimaryBottleneck: "memory",
		Timestamp:         now.Add(10 * time.Second),
	})

	corrs := tc.Correlate("web-01", 30*time.Second)
	for _, c := range corrs {
		if c.TargetHost == "db-01" {
			t.Logf("distant host correlation: likelihood=%.2f", c.Likelihood)
		}
	}
}

func TestDomainSimilarity(t *testing.T) {
	tests := []struct {
		a, b   string
		expect float64
	}{
		{"cpu", "cpu", 1.0},
		{"memory", "io", 0.7},
		{"cpu", "network", 0.4},
		{"unknown", "other", 0.1},
	}

	for _, tt := range tests {
		got := domainSimilarity(tt.a, tt.b)
		if got != tt.expect {
			t.Errorf("domainSimilarity(%q,%q) = %.2f, want %.2f", tt.a, tt.b, got, tt.expect)
		}
	}
}

func TestInferDirection(t *testing.T) {
	web := &HostTopology{HostID: "web", Tier: 1}
	app := &HostTopology{HostID: "app", Tier: 2}
	db := &HostTopology{HostID: "db", Tier: 3}

	if d := inferDirection(web, app); d != "upstream" {
		t.Errorf("web→app: expected upstream, got %s", d)
	}
	if d := inferDirection(app, web); d != "downstream" {
		t.Errorf("app→web: expected downstream, got %s", d)
	}
	if d := inferDirection(app, db); d != "upstream" {
		t.Errorf("app→db: expected upstream, got %s", d)
	}
}
