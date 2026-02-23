package collector

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Fix #43 – safeSubU64: prevent uint64 underflow when b > a
// ---------------------------------------------------------------------------

func TestSafeSubU64_NormalSubtraction(t *testing.T) {
	got := safeSubU64(10, 5)
	if got != 5 {
		t.Errorf("safeSubU64(10, 5) = %d; want 5", got)
	}
}

func TestSafeSubU64_UnderflowClampsToZero(t *testing.T) {
	got := safeSubU64(5, 10)
	if got != 0 {
		t.Errorf("safeSubU64(5, 10) = %d; want 0", got)
	}
}

func TestSafeSubU64_BothZero(t *testing.T) {
	got := safeSubU64(0, 0)
	if got != 0 {
		t.Errorf("safeSubU64(0, 0) = %d; want 0", got)
	}
}

func TestSafeSubU64_EqualValues(t *testing.T) {
	got := safeSubU64(42, 42)
	if got != 0 {
		t.Errorf("safeSubU64(42, 42) = %d; want 0", got)
	}
}

func TestSafeSubU64_MaxUint64(t *testing.T) {
	var maxU64 uint64 = ^uint64(0)
	got := safeSubU64(maxU64, 1)
	want := maxU64 - 1
	if got != want {
		t.Errorf("safeSubU64(maxU64, 1) = %d; want %d", got, want)
	}
}

func TestSafeSubU64_ZeroMinusOne(t *testing.T) {
	got := safeSubU64(0, 1)
	if got != 0 {
		t.Errorf("safeSubU64(0, 1) = %d; want 0 (would wrap without fix)", got)
	}
}

// ---------------------------------------------------------------------------
// Fix #24 – parseHex64: nf_conntrack stat file uses hex values
// ---------------------------------------------------------------------------

func TestParseHex64_LowercaseHex(t *testing.T) {
	got := parseHex64("1a")
	if got != 26 {
		t.Errorf("parseHex64(\"1a\") = %d; want 26", got)
	}
}

func TestParseHex64_FF(t *testing.T) {
	got := parseHex64("ff")
	if got != 255 {
		t.Errorf("parseHex64(\"ff\") = %d; want 255", got)
	}
}

func TestParseHex64_Zero(t *testing.T) {
	got := parseHex64("0")
	if got != 0 {
		t.Errorf("parseHex64(\"0\") = %d; want 0", got)
	}
}

func TestParseHex64_EmptyString(t *testing.T) {
	got := parseHex64("")
	if got != 0 {
		t.Errorf("parseHex64(\"\") = %d; want 0", got)
	}
}

func TestParseHex64_InvalidString(t *testing.T) {
	got := parseHex64("invalid")
	if got != 0 {
		t.Errorf("parseHex64(\"invalid\") = %d; want 0", got)
	}
}

func TestParseHex64_UppercaseHex(t *testing.T) {
	got := parseHex64("FF")
	if got != 255 {
		t.Errorf("parseHex64(\"FF\") = %d; want 255", got)
	}
}

func TestParseHex64_LeadingWhitespace(t *testing.T) {
	got := parseHex64("  1a")
	if got != 26 {
		t.Errorf("parseHex64(\"  1a\") = %d; want 26 (TrimSpace should handle leading whitespace)", got)
	}
}

func TestParseHex64_TrailingWhitespace(t *testing.T) {
	got := parseHex64("ff  ")
	if got != 255 {
		t.Errorf("parseHex64(\"ff  \") = %d; want 255 (TrimSpace should handle trailing whitespace)", got)
	}
}

func TestParseHex64_LargeValue(t *testing.T) {
	// ffffffff = 4294967295
	got := parseHex64("ffffffff")
	if got != 4294967295 {
		t.Errorf("parseHex64(\"ffffffff\") = %d; want 4294967295", got)
	}
}

// ---------------------------------------------------------------------------
// Fix #27 – filelessParseRemoteIP: parse /proc/net/tcp{,6} rem_address
// ---------------------------------------------------------------------------

func TestFilelessParseRemoteIP_IPv4(t *testing.T) {
	// /proc/net/tcp encodes IPv4 in little-endian hex: 0100007F = 127.0.0.1
	// bytes after hex.DecodeString("0100007F") = [0x01, 0x00, 0x00, 0x7F]
	// reversed (b[3].b[2].b[1].b[0]) = 127.0.0.1
	got := filelessParseRemoteIP("0100007F:0050")
	if got != "127.0.0.1" {
		t.Errorf("filelessParseRemoteIP(\"0100007F:0050\") = %q; want \"127.0.0.1\"", got)
	}
}

func TestFilelessParseRemoteIP_IPv4_ExternalAddr(t *testing.T) {
	// 0101A8C0 → hex decode → [0x01, 0x01, 0xA8, 0xC0] → reversed: 192.168.1.1
	got := filelessParseRemoteIP("0101A8C0:01BB")
	if got != "192.168.1.1" {
		t.Errorf("filelessParseRemoteIP(\"0101A8C0:01BB\") = %q; want \"192.168.1.1\"", got)
	}
}

func TestFilelessParseRemoteIP_IPv4_AllZeros(t *testing.T) {
	got := filelessParseRemoteIP("00000000:0000")
	if got != "0.0.0.0" {
		t.Errorf("filelessParseRemoteIP(\"00000000:0000\") = %q; want \"0.0.0.0\"", got)
	}
}

func TestFilelessParseRemoteIP_IPv6_Loopback(t *testing.T) {
	// IPv6 loopback ::1
	// /proc/net/tcp6 on little-endian prints each __be32 with byte reversal.
	// ::1 in network order = 00000000 00000000 00000000 00000001
	// Each 4-byte group reversed on LE: 00000000 00000000 00000000 01000000
	got := filelessParseRemoteIP("00000000000000000000000001000000:0050")
	if got != "0:0:0:0:0:0:0:1" {
		t.Errorf("filelessParseRemoteIP(IPv6 loopback) = %q; want \"0:0:0:0:0:0:0:1\"", got)
	}
}

func TestFilelessParseRemoteIP_IPv4MappedIPv6(t *testing.T) {
	// IPv4-mapped IPv6 for 192.168.1.1 = ::ffff:192.168.1.1
	// Network order bytes: 00 00 00 00 | 00 00 00 00 | 00 00 FF FF | C0 A8 01 01
	// Each 4-byte group reversed (LE kernel /proc format):
	//   "00000000" "00000000" "FFFF0000" "0101A8C0"
	got := filelessParseRemoteIP("0000000000000000FFFF00000101A8C0:01BB")
	if got != "192.168.1.1" {
		t.Errorf("filelessParseRemoteIP(IPv4-mapped IPv6 192.168.1.1) = %q; want \"192.168.1.1\"", got)
	}
}

func TestFilelessParseRemoteIP_IPv6_FullAddress(t *testing.T) {
	// 2001:0db8::1 in network order: 20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01
	// Each 4-byte group reversed for LE /proc format:
	//   "B80D0120" "00000000" "00000000" "01000000"
	got := filelessParseRemoteIP("B80D0120000000000000000001000000:0050")
	if got != "2001:db8:0:0:0:0:0:1" {
		t.Errorf("filelessParseRemoteIP(IPv6 2001:db8::1) = %q; want \"2001:db8:0:0:0:0:0:1\"", got)
	}
}

func TestFilelessParseRemoteIP_EmptyString(t *testing.T) {
	got := filelessParseRemoteIP("")
	if got != "" {
		t.Errorf("filelessParseRemoteIP(\"\") = %q; want \"\"", got)
	}
}

func TestFilelessParseRemoteIP_NoColonSeparator(t *testing.T) {
	got := filelessParseRemoteIP("0100007F")
	if got != "" {
		t.Errorf("filelessParseRemoteIP(\"0100007F\") = %q; want \"\" (no port separator)", got)
	}
}

func TestFilelessParseRemoteIP_InvalidHex(t *testing.T) {
	got := filelessParseRemoteIP("ZZZZZZZZ:0050")
	if got != "" {
		t.Errorf("filelessParseRemoteIP(\"ZZZZZZZZ:0050\") = %q; want \"\"", got)
	}
}

func TestFilelessParseRemoteIP_OddLengthHex(t *testing.T) {
	// Odd number of hex chars cannot be decoded
	got := filelessParseRemoteIP("0100007:0050")
	if got != "" {
		t.Errorf("filelessParseRemoteIP(\"0100007:0050\") = %q; want \"\" (odd-length hex)", got)
	}
}

func TestFilelessParseRemoteIP_WrongByteLength(t *testing.T) {
	// 6 bytes is neither IPv4 (4) nor IPv6 (16)
	got := filelessParseRemoteIP("010000070000:0050")
	// 12 hex chars = 6 bytes → not 4 or 16 → should return ""
	if got != "" {
		t.Errorf("filelessParseRemoteIP(6 bytes) = %q; want \"\"", got)
	}
}
