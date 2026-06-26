package identity

// Tests for the pure classification helpers: hasListeningPort,
// hasRunningService, and the score-based role classifiers.
// No I/O, no live sockets, no root required.

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// ─── hasListeningPort ─────────────────────────────────────────────────────────

func TestHasListeningPort_Found(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Ports: []int{80, 443}},
		},
	}
	if !hasListeningPort(id, 80) {
		t.Error("expected port 80 to be found")
	}
	if !hasListeningPort(id, 443) {
		t.Error("expected port 443 to be found")
	}
}

func TestHasListeningPort_NotFound(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Ports: []int{80, 443}},
		},
	}
	if hasListeningPort(id, 3306) {
		t.Error("expected port 3306 not to be found")
	}
}

func TestHasListeningPort_Empty(t *testing.T) {
	id := &model.ServerIdentity{}
	if hasListeningPort(id, 80) {
		t.Error("expected no ports on empty identity")
	}
}

func TestHasListeningPort_MultipleServices(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Ports: []int{80}},
			{Name: "mysql", Ports: []int{3306}},
		},
	}
	if !hasListeningPort(id, 3306) {
		t.Error("expected port 3306 from mysql service")
	}
	if hasListeningPort(id, 5432) {
		t.Error("expected port 5432 not found")
	}
}

func TestHasListeningPort_MultipleTargetPorts(t *testing.T) {
	// Check any-of behavior: hasListeningPort(id, 5432, 3306, 27017, ...)
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "redis", Ports: []int{6379}},
		},
	}
	if !hasListeningPort(id, 5432, 3306, 6379) {
		t.Error("expected port 6379 matched via multi-target call")
	}
	if hasListeningPort(id, 5432, 3306) {
		t.Error("expected no match when none of the targets present")
	}
}

// ─── hasRunningService ────────────────────────────────────────────────────────

func TestHasRunningService_Found(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Running: true},
		},
	}
	if !hasRunningService(id, "nginx") {
		t.Error("expected nginx to be running")
	}
}

func TestHasRunningService_NotRunning(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Running: false},
		},
	}
	if hasRunningService(id, "nginx") {
		t.Error("expected nginx not running (Running=false)")
	}
}

func TestHasRunningService_Missing(t *testing.T) {
	id := &model.ServerIdentity{}
	if hasRunningService(id, "mysql") {
		t.Error("expected no match on empty identity")
	}
}

func TestHasRunningService_MultipleNames(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "postgresql", Running: true},
		},
	}
	if !hasRunningService(id, "mysql", "postgresql", "mongodb") {
		t.Error("expected postgresql matched via multi-name call")
	}
	if hasRunningService(id, "mysql", "mongodb") {
		t.Error("expected no match when postgresql not in candidate list")
	}
}

// ─── scoreWebServer ───────────────────────────────────────────────────────────

func TestScoreWebServer_NginxOnStandardPort(t *testing.T) {
	// nginx running + port 80 → score well above 35 threshold.
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Running: true, Ports: []int{80, 443}},
		},
	}
	a := scoreWebServer(id)
	if a.role != model.RoleWebServer {
		t.Errorf("unexpected role %q", a.role)
	}
	if a.score < 35 {
		t.Errorf("expected score ≥ 35 for nginx+port80; got %d", a.score)
	}
}

func TestScoreWebServer_NoSignals(t *testing.T) {
	id := &model.ServerIdentity{}
	a := scoreWebServer(id)
	if a.score >= 35 {
		t.Errorf("expected score < 35 with no signals; got %d", a.score)
	}
}

// ─── scoreDatabase ────────────────────────────────────────────────────────────

func TestScoreDatabase_MySQLRunning(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "mysql", Running: true, Ports: []int{3306}},
		},
		Databases: []model.DatabaseInfo{
			{Engine: "mysql", Name: "mydb"},
		},
	}
	a := scoreDatabase(id)
	if a.score < 35 {
		t.Errorf("expected score ≥ 35 for mysql+port3306+db; got %d", a.score)
	}
}

func TestScoreDatabase_NoSignals(t *testing.T) {
	id := &model.ServerIdentity{}
	a := scoreDatabase(id)
	if a.score >= 35 {
		t.Errorf("expected score < 35 with no signals; got %d", a.score)
	}
}

// ─── scoreDockerHost ──────────────────────────────────────────────────────────

func TestScoreDockerHost_DockerRunningWithContainers(t *testing.T) {
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "docker", Running: true},
		},
		Containers: []model.DockerContainer{
			{ID: "abc123", Name: "myapp", Status: "running"},
			{ID: "def456", Name: "redis", Status: "running"},
		},
	}
	a := scoreDockerHost(id)
	if a.score < 35 {
		t.Errorf("expected score ≥ 35 for docker+containers; got %d", a.score)
	}
}

func TestScoreDockerHost_NoDocker(t *testing.T) {
	id := &model.ServerIdentity{}
	a := scoreDockerHost(id)
	if a.score >= 35 {
		t.Errorf("expected score < 35 with no Docker; got %d", a.score)
	}
}

// ─── classifyRoles ────────────────────────────────────────────────────────────

func TestClassifyRoles_WebServerAssigned(t *testing.T) {
	// Full nginx setup should reach the 35-point threshold.
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "nginx", Running: true, Ports: []int{80, 443}},
		},
		Websites: []model.WebsiteInfo{{Domain: "example.com", Port: 443}},
	}
	classifyRoles(id)
	if !id.HasRole(model.RoleWebServer) {
		t.Errorf("expected RoleWebServer to be assigned; roles=%v", id.Roles)
	}
}

func TestClassifyRoles_EmptyIdentity(t *testing.T) {
	// With a fully empty identity, identity-based signals (services,
	// containers, ports, databases, etc.) contribute zero points.
	// Some scorers (NAT, router, firewall) also probe live system state
	// (iptables, interfaces, routes) which may produce non-zero scores on
	// a live Linux host — so we only assert that service-based roles are
	// absent rather than requiring an empty slice.
	id := &model.ServerIdentity{}
	classifyRoles(id)
	for _, r := range id.Roles {
		switch r {
		case model.RoleWebServer, model.RoleDatabaseServer,
			model.RoleDockerHost, model.RoleK8sNode,
			model.RoleMailServer, model.RoleDNSServer,
			model.RoleCICDRunner, model.RoleMonitoringServer,
			model.RoleVPNServer:
			t.Errorf("unexpected service-based role %q on empty identity", r)
		}
	}
}

func TestClassifyRoles_DatabaseAndDockerCoexist(t *testing.T) {
	// Both a database service and Docker can coexist.
	id := &model.ServerIdentity{
		Services: []model.DetectedService{
			{Name: "postgresql", Running: true, Ports: []int{5432}},
			{Name: "docker", Running: true},
		},
		Databases: []model.DatabaseInfo{{Engine: "postgresql", Name: "app"}},
		Containers: []model.DockerContainer{
			{ID: "c1", Name: "app", Status: "running"},
		},
	}
	classifyRoles(id)
	if !id.HasRole(model.RoleDatabaseServer) {
		t.Errorf("expected RoleDatabaseServer; roles=%v", id.Roles)
	}
	if !id.HasRole(model.RoleDockerHost) {
		t.Errorf("expected RoleDockerHost; roles=%v", id.Roles)
	}
}

// ─── parseLocalPort ───────────────────────────────────────────────────────────

func TestParseLocalPort_Valid(t *testing.T) {
	cases := []struct {
		addr string
		want int
	}{
		// /proc/net/tcp local_address field: IP:PORT both hex, port big-endian
		{"00000000:0050", 80},   // port 80
		{"00000000:01BB", 443},  // port 443
		{"00000000:0CEA", 3306}, // port 3306
	}
	for _, tc := range cases {
		got := parseLocalPort(tc.addr)
		if got != tc.want {
			t.Errorf("parseLocalPort(%q) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}

func TestParseLocalPort_Invalid(t *testing.T) {
	cases := []string{
		"",
		"badformat",
		"00000000",   // no colon
		"00000000:",  // empty port part
	}
	for _, tc := range cases {
		got := parseLocalPort(tc)
		if got != 0 {
			t.Errorf("parseLocalPort(%q) = %d, want 0", tc, got)
		}
	}
}
