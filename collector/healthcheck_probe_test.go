//go:build linux

package collector

import (
	"net"
	"testing"
)

// TestProbeHTTPListeningButNoResponseNotCrit reproduces the false-CRIT bug: a
// server that accepts the TCP connection but sends no HTTP response (e.g. nginx
// `return 444` on a vhost-only server, which xtop probes as bare 127.0.0.1 with
// no Host header) must NOT be reported as down/CRIT — the service is up.
func TestProbeHTTPListeningButNoResponseNotCrit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Accept every connection and immediately close it — no HTTP reply.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	r := probeHTTP(probeTarget{name: "t", probeType: "http", target: "http://" + ln.Addr().String() + "/"})
	if r.Status == "CRIT" {
		t.Fatalf("a listening port with no HTTP reply must not be CRIT (service is up); got CRIT: %q", r.Detail)
	}
}

// TestProbeHTTPPortClosedIsCrit guards the real-down case: nothing listening →
// connection refused → CRIT.
func TestProbeHTTPPortClosedIsCrit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // free the port so a connect is refused

	r := probeHTTP(probeTarget{name: "t", probeType: "http", target: "http://" + addr + "/"})
	if r.Status != "CRIT" {
		t.Fatalf("a genuinely down (refused) port must be CRIT; got %q (%s)", r.Status, r.Detail)
	}
}
