package collector

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHaproxySocketCmd verifies that haproxySocketCmd connects to a Unix socket,
// sends the command, and returns the canned response — no shell or socat involved.
func TestHaproxySocketCmd(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "haproxy.sock")

	const cannedStat = "# pxname,svname,qcur,qmax,scur\nfrontend,FRONTEND,0,0,1\n"

	// Start a tiny Unix-socket echo server that returns canned output.
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Listen unix %s: %v", sockPath, err)
	}
	defer ln.Close()
	defer os.Remove(sockPath)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(cannedStat))
			}(conn)
		}
	}()

	got, err := haproxySocketCmd(sockPath, "show stat")
	if err != nil {
		t.Fatalf("haproxySocketCmd returned error: %v", err)
	}
	if !strings.Contains(got, "FRONTEND") {
		t.Errorf("haproxySocketCmd response missing expected content; got: %q", got)
	}
	if got != cannedStat {
		t.Errorf("haproxySocketCmd response mismatch:\ngot:  %q\nwant: %q", got, cannedStat)
	}
}

// TestHaproxySocketCmd_ConnError verifies that a missing socket returns an error.
func TestHaproxySocketCmd_ConnError(t *testing.T) {
	t.Parallel()

	_, err := haproxySocketCmd("/nonexistent/socket.sock", "show stat")
	if err == nil {
		t.Error("expected error for nonexistent socket, got nil")
	}
}
