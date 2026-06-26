package apps

import (
	"strings"
	"testing"
)

// Minimal "show stat" CSV exercising only the fields our tests assert on.
// The parser uses a name-indexed column lookup, so we only need columns that
// appear in the header — unused columns can be omitted.
const haproxyStatCSV = `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,req_rate,req_tot,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,cli_abrt,srv_abrt,check_status,check_code,addr,mode
http-in,FRONTEND,0,0,3,120,2000,458231,89341231,7812394811,0,0,42,0,0,0,0,OPEN,65,458231,415823,31402,8743,2263,0,0,,,http,http
backend1,BACKEND,0,5,2,30,,12405,234523,4512344,0,0,,14,34,5,2,UP,,12405,11230,450,654,71,0,0,,,http,http
backend1,srv1,0,2,1,10,50,4100,87234,1523452,,,,,8,3,1,UP,,,3980,60,42,18,,,L7OK,200,192.168.1.10:8080,http
`

// representative "show info" output.
const haproxyInfoRaw = `Name: HAProxy
Version: 2.6.14-2d0e2024
Release_date: 2023/09/11
Nbthread: 4
Nbproc: 1
Process_num: 1
Pid: 12345
Uptime: 7d 2h15m33s
Uptime_sec: 614133
Memmax_MB: 0
PoolAlloc_MB: 5
PoolUsed_MB: 4
PoolFailed: 0
Ulimit-n: 200027
Maxsock: 200027
Maxconn: 100000
HardMaxconn: 100000
CurrConns: 3
MaxConn: 3
Listeners: 1
MaxPipes: 0
PipesUsed: 0
PipesFree: 0
ConnRate: 0
ConnRateLimit: 0
MaxConnRate: 0
SessRate: 0
SessRateLimit: 0
MaxSessRate: 4
SessRateLimitPct: 0
Run_queue: 0
Idle_pct: 100
node: mynode
`

// ────────────────────────────────────────────────────────────────────────────
// parseHAProxyInfo tests
// ────────────────────────────────────────────────────────────────────────────

func TestParseHAProxyInfo_wellFormed(t *testing.T) {
	m := parseHAProxyInfo(haproxyInfoRaw)

	cases := []struct{ key, want string }{
		{"Version", "2.6.14-2d0e2024"},
		{"Uptime_sec", "614133"},
		{"Maxconn", "100000"}, // lowercase 'c' is the configured max-connections key
		{"CurrConns", "3"},
		{"MaxConn", "3"}, // uppercase MaxConn is the live metric ("current max conn in use")
		{"node", "mynode"},
	}
	for _, c := range cases {
		if got := m[c.key]; got != c.want {
			t.Errorf("parseHAProxyInfo[%q] = %q, want %q", c.key, got, c.want)
		}
	}
}

func TestParseHAProxyInfo_malformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"no colon", "Version 2.6\nPid 1"},
		{"only whitespace", "   \n\t\n"},
		{"truncated line", "Version:"},
		{"garbage", "\x00\xff\xfe garbage binary data \n: val"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// must not panic, must return a map (possibly empty)
			m := parseHAProxyInfo(c.raw)
			if m == nil {
				t.Error("expected non-nil map even for malformed input")
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// parseHAProxyStats tests
// ────────────────────────────────────────────────────────────────────────────

func TestParseHAProxyStats_frontend(t *testing.T) {
	rows := parseHAProxyStats(haproxyStatCSV)
	if len(rows) == 0 {
		t.Fatal("expected rows, got none")
	}

	var fe *haproxyStatRow
	for i := range rows {
		if rows[i].svname == "FRONTEND" {
			fe = &rows[i]
			break
		}
	}
	if fe == nil {
		t.Fatal("no FRONTEND row found")
	}
	if fe.pxname != "http-in" {
		t.Errorf("FRONTEND pxname = %q, want %q", fe.pxname, "http-in")
	}
	if fe.status != "OPEN" {
		t.Errorf("FRONTEND status = %q, want %q", fe.status, "OPEN")
	}
	if fe.stot != 458231 {
		t.Errorf("FRONTEND stot = %d, want 458231", fe.stot)
	}
	if fe.ereq != 42 {
		t.Errorf("FRONTEND ereq = %d, want 42", fe.ereq)
	}
	if fe.hrsp4xx != 8743 {
		t.Errorf("FRONTEND hrsp4xx = %d, want 8743", fe.hrsp4xx)
	}
	if fe.hrsp5xx != 2263 {
		t.Errorf("FRONTEND hrsp5xx = %d, want 2263", fe.hrsp5xx)
	}
	if fe.reqTot != 458231 {
		t.Errorf("FRONTEND req_tot = %d, want 458231", fe.reqTot)
	}
	if fe.reqRate != 65 {
		t.Errorf("FRONTEND req_rate = %d, want 65", fe.reqRate)
	}
}

func TestParseHAProxyStats_backend(t *testing.T) {
	rows := parseHAProxyStats(haproxyStatCSV)

	var be *haproxyStatRow
	for i := range rows {
		if rows[i].svname == "BACKEND" {
			be = &rows[i]
			break
		}
	}
	if be == nil {
		t.Fatal("no BACKEND row found")
	}
	if be.pxname != "backend1" {
		t.Errorf("BACKEND pxname = %q, want %q", be.pxname, "backend1")
	}
	if be.status != "UP" {
		t.Errorf("BACKEND status = %q, want %q", be.status, "UP")
	}
	if be.qcur != 0 {
		t.Errorf("BACKEND qcur = %d, want 0", be.qcur)
	}
	if be.qmax != 5 {
		t.Errorf("BACKEND qmax = %d, want 5", be.qmax)
	}
	if be.eresp != 34 {
		t.Errorf("BACKEND eresp = %d, want 34", be.eresp)
	}
}

func TestParseHAProxyStats_server(t *testing.T) {
	rows := parseHAProxyStats(haproxyStatCSV)

	var srv *haproxyStatRow
	for i := range rows {
		if rows[i].svname == "srv1" {
			srv = &rows[i]
			break
		}
	}
	if srv == nil {
		t.Fatal("no server row (srv1) found")
	}
	if srv.status != "UP" {
		t.Errorf("srv1 status = %q, want UP", srv.status)
	}
	if srv.addr != "192.168.1.10:8080" {
		t.Errorf("srv1 addr = %q, want 192.168.1.10:8080", srv.addr)
	}
	if srv.checkStatus != "L7OK" {
		t.Errorf("srv1 check_status = %q, want L7OK", srv.checkStatus)
	}
	if srv.checkCode != 200 {
		t.Errorf("srv1 check_code = %d, want 200", srv.checkCode)
	}
	if srv.hrsp5xx != 18 {
		t.Errorf("srv1 hrsp_5xx = %d, want 18", srv.hrsp5xx)
	}
}

func TestParseHAProxyStats_rowCount(t *testing.T) {
	rows := parseHAProxyStats(haproxyStatCSV)
	// expect exactly 3 rows: FRONTEND, BACKEND, srv1
	if len(rows) != 3 {
		t.Errorf("expected 3 rows, got %d", len(rows))
	}
}

func TestParseHAProxyStats_malformed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty string", ""},
		{"header only", "# pxname,svname,qcur,status\n"},
		{"non-csv garbage", "this is not csv at all\x00\xff"},
		{"truncated row", "# pxname,svname,status\nfrontend,FRONTEND"},
		{"whitespace only", "   \n\n\t\n"},
		{"single comma", ","},
		{"header no rows", "pxname,svname,status\n"},
		{"very long line", "# pxname,svname,status\n" + strings.Repeat("x,", 1000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// must not panic; result may be nil or empty slice — both acceptable
			rows := parseHAProxyStats(c.raw)
			_ = rows // we only care about no panic
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Fuzz target for parseHAProxyStats
// ────────────────────────────────────────────────────────────────────────────

// FuzzParseHAProxyStats exercises the CSV parser with arbitrary input.
// Run: go test ./collector/apps/ -run FuzzParseHAProxyStats        (seed corpus)
//
//	go test ./collector/apps/ -fuzz FuzzParseHAProxyStats -fuzztime 30s
func FuzzParseHAProxyStats(f *testing.F) {
	// Seed corpus
	f.Add(haproxyStatCSV)
	f.Add("")
	f.Add("# pxname,svname,status\n")
	f.Add("garbage,not,csv\x00\xff\xfe")
	f.Add("# pxname,svname,status\nfrontend,FRONTEND,OPEN\nbackend,BACKEND,UP")
	f.Add(strings.Repeat("a,", 500) + "\n" + strings.Repeat("b,", 500))
	f.Add("# " + strings.Repeat("col,", 100) + "\n" + strings.Repeat("val,", 100))

	f.Fuzz(func(t *testing.T, data string) {
		// Must never panic
		_ = parseHAProxyStats(data)
	})
}
