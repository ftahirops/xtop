//go:build linux

package apps

import (
	"strings"
	"testing"
)

// ── S1: MySQL password must not appear in CLI args ──────────────────────────

func TestMysqlCLIArgs_noPassword(t *testing.T) {
	secrets := &AppSecrets{MySQL: &DBCreds{
		User:     "root",
		Password: "supersecret",
		Host:     "127.0.0.1",
		Port:     3306,
	}}
	args := mysqlCLIArgs(secrets)
	for _, a := range args {
		if strings.Contains(a, "supersecret") {
			t.Errorf("password found in CLI args: %v", args)
		}
		if strings.HasPrefix(a, "-p") {
			t.Errorf("-p flag found in CLI args: %v", args)
		}
	}
	// User and host must still be present
	found := map[string]bool{}
	for i, a := range args {
		if a == "-u" && i+1 < len(args) {
			found["user"] = true
		}
		if a == "-h" && i+1 < len(args) {
			found["host"] = true
		}
	}
	if !found["user"] {
		t.Error("expected -u user in args")
	}
	if !found["host"] {
		t.Error("expected -h host in args")
	}
}

func TestMysqlEnv_setsPassword(t *testing.T) {
	secrets := &AppSecrets{MySQL: &DBCreds{Password: "s3cr3t"}}
	env := mysqlEnv(secrets)
	if len(env) != 1 {
		t.Fatalf("expected 1 env entry, got %d", len(env))
	}
	if env[0] != "MYSQL_PWD=s3cr3t" {
		t.Errorf("unexpected env entry: %s", env[0])
	}
}

func TestMysqlEnv_emptyPasswordNoEntry(t *testing.T) {
	secrets := &AppSecrets{MySQL: &DBCreds{User: "root", Password: ""}}
	env := mysqlEnv(secrets)
	if len(env) != 0 {
		t.Errorf("expected no env entries for empty password, got %v", env)
	}
}

func TestMysqlEnv_nilSecrets(t *testing.T) {
	env := mysqlEnv(nil)
	if len(env) != 0 {
		t.Errorf("expected no env entries for nil secrets, got %v", env)
	}
}

// ── P1: btime must be cached after first read ────────────────────────────────

func TestCachedBtime_returnsPositive(t *testing.T) {
	// Reset cache for test isolation
	btimeMu.Lock()
	btimeCached = 0
	btimeMu.Unlock()

	bt := cachedBtime()
	if bt <= 0 {
		t.Fatalf("expected positive boot time, got %v", bt)
	}
}

func TestCachedBtime_stableAcrossCalls(t *testing.T) {
	btimeMu.Lock()
	btimeCached = 0
	btimeMu.Unlock()

	bt1 := cachedBtime()
	bt2 := cachedBtime()
	bt3 := cachedBtime()
	if bt1 != bt2 || bt2 != bt3 {
		t.Errorf("btime not stable: %v %v %v", bt1, bt2, bt3)
	}
	// After first call the cache must be populated.
	btimeMu.Lock()
	cached := btimeCached
	btimeMu.Unlock()
	if cached == 0 {
		t.Error("btimeCached should be set after successful read")
	}
}

func TestReadProcUptime_sanity(t *testing.T) {
	// Reset cache
	btimeMu.Lock()
	btimeCached = 0
	btimeMu.Unlock()

	// PID 1 (init/systemd) is always long-running; avoids the sub-second truncation
	// that hits os.Getpid() when the test process itself just started.
	uptime := readProcUptime(1)
	if uptime <= 0 {
		t.Errorf("expected positive uptime for pid 1, got %d", uptime)
	}
}
