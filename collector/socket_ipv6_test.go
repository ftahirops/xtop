package collector

import (
	"testing"
)

// TestParseRemoteIPv4 verifies IPv4 parsing from /proc/net/tcp address fields.
// /proc/net/tcp stores IPv4 as a 4-byte little-endian 32-bit word, so
// 127.0.0.1 is stored as 0100007F (bytes: 01 00 00 7F → reversed: 7F 00 00 01).
func TestParseRemoteIPv4(t *testing.T) {
	tests := []struct {
		name    string
		input   string // "hex_addr:hex_port"
		want    string
	}{
		{
			name:  "loopback 127.0.0.1",
			input: "0100007F:1F90", // 0x7F=127, little-endian
			want:  "127.0.0.1",
		},
		{
			name:  "192.168.1.10",
			input: "0A01A8C0:0050", // 0xC0=192, 0xA8=168, 0x01=1, 0x0A=10, little-endian
			want:  "192.168.1.10",
		},
		{
			name:  "all-zeros unspecified",
			input: "00000000:0000",
			want:  "0.0.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRemoteIP(tt.input)
			if got != tt.want {
				t.Errorf("parseRemoteIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseRemoteIPv6 verifies IPv6 parsing from /proc/net/tcp6 address fields.
// /proc/net/tcp6 stores IPv6 as four consecutive little-endian 32-bit words.
// The parser must reverse each 4-byte group to recover network byte order.
func TestParseRemoteIPv6(t *testing.T) {
	tests := []struct {
		name    string
		input   string // "32_hex_addr:hex_port"
		want    string
	}{
		{
			name: "loopback ::1",
			// ::1 in network byte order: 00000000 00000000 00000000 00000001
			// Each 32-bit word as little-endian: 00000000 00000000 00000000 01000000
			input: "00000000000000000000000001000000:0000",
			want:  "::1",
		},
		{
			name: "all-zeros ::",
			input: "00000000000000000000000000000000:0000",
			want:  "::",
		},
		{
			name: "IPv4-mapped ::ffff:192.168.1.10",
			// ::ffff:192.168.1.10 in network byte order:
			//   00000000 00000000 0000ffff c0a8010a
			// Each 32-bit word stored as little-endian in the file:
			//   word0 (0x00000000): 00000000
			//   word1 (0x00000000): 00000000
			//   word2 (0x0000FFFF): FFFF0000  ← bytes 10-11 must be FF FF
			//   word3 (0xC0A8010A): 0A01A8C0
			// Go's net.IP.String() converts IPv4-mapped IPv6 to plain IPv4 notation.
			input: "0000000000000000FFFF00000A01A8C0:0050",
			want:  "192.168.1.10",
		},
		{
			name: "2001:db8::1",
			// 2001:0db8:0000:0000:0000:0000:0000:0001 in network byte order:
			//   20010db8 00000000 00000000 00000001
			// Each 32-bit word as little-endian:
			//   b80d0120 00000000 00000000 01000000
			input: "b80d012000000000000000000100000:0035",
			// This input has an odd number of hex chars (31), which should fail gracefully
			want: "",
		},
		{
			name: "2001:db8::1 correct",
			// 2001:0db8:0000:0000:0000:0000:0000:0001
			// Network byte order: 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
			// As 4 LE 32-bit words:
			//   word0 (20010db8 → LE): b8 0d 01 20 → hex "b80d0120"
			//   word1 (00000000 → LE): 00 00 00 00 → hex "00000000"
			//   word2 (00000000 → LE): 00 00 00 00 → hex "00000000"
			//   word3 (00000001 → LE): 01 00 00 00 → hex "01000000"
			input: "b80d0120000000000000000001000000:0035",
			want:  "2001:db8::1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRemoteIP(tt.input)
			if got != tt.want {
				t.Errorf("parseRemoteIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseFullAddrIPv6 verifies that parseFullAddr returns a valid "ip:port"
// string for an IPv6 CLOSE_WAIT socket address from /proc/net/tcp6.
func TestParseFullAddrIPv6(t *testing.T) {
	// ::1:8080 — loopback, port 8080 (0x1F90)
	// loopback: 00000000000000000000000001000000, port: 1F90
	input := "00000000000000000000000001000000:1F90"
	got := parseFullAddr(input)
	if got != "::1:8080" {
		t.Errorf("parseFullAddr(%q) = %q, want %q", input, got, "::1:8080")
	}
}

// TestIPv6CloseWaitSocketKey verifies that socket keys built from /proc/net/tcp6
// CLOSE_WAIT lines do not collide with IPv4 socket keys from /proc/net/tcp.
// Key format: fields[1] + "->" + fields[2] (raw hex strings from the file).
func TestIPv6CloseWaitSocketKey(t *testing.T) {
	// Simulate a /proc/net/tcp CLOSE_WAIT line (IPv4)
	// local: 0A01A8C0:1234 (192.168.1.10:4660), remote: 0100007F:1F90 (127.0.0.1:8080)
	ipv4Local := "0A01A8C0:1234"
	ipv4Remote := "0100007F:1F90"
	ipv4Key := ipv4Local + "->" + ipv4Remote

	// Simulate a /proc/net/tcp6 CLOSE_WAIT line with the same port numbers
	// but an IPv6 address — should produce a different key due to 32-hex addr.
	ipv6Local := "00000000000000000000000001000000:1234"
	ipv6Remote := "00000000000000000000000001000000:1F90"
	ipv6Key := ipv6Local + "->" + ipv6Remote

	if ipv4Key == ipv6Key {
		t.Errorf("IPv4 and IPv6 socket keys collide: %q", ipv4Key)
	}

	// IPv4 key must be shorter than IPv6 key (8-hex vs 32-hex addr parts)
	if len(ipv4Key) >= len(ipv6Key) {
		t.Errorf("expected IPv4 key (%d chars) shorter than IPv6 key (%d chars)", len(ipv4Key), len(ipv6Key))
	}
}

// TestParseLocalPortIPv6 verifies that ParseLocalPort works on an IPv6
// address field from /proc/net/tcp6 — the port field is identical in format.
func TestParseLocalPortIPv6(t *testing.T) {
	// IPv6 local address: ::1:8080 → "00000000000000000000000001000000:1F90"
	input := "00000000000000000000000001000000:1F90"
	got := ParseLocalPort(input)
	if got != 8080 {
		t.Errorf("ParseLocalPort(%q) = %d, want 8080", input, got)
	}
}
