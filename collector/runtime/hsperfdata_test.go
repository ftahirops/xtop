package runtime

import (
	"encoding/binary"
	"testing"
)

// buildHsperfdataFixture builds a minimal valid hsperfdata blob with the
// given little-endian long ('J') counters, so we can test doParseHsperfdata
// without touching the filesystem.
//
// Layout used:
//
//	[0:4]   magic (LE: 0xC0C0FECA)
//	[4]     byte_order = 1 (little-endian)
//	[5]     major = 2
//	[6]     minor = 0
//	[7]     reserved
//	[8:12]  entry_offset = 16 (header ends at 16)
//	[12:16] num_entries = N
//
// Each entry:
//
//	[0:4]   entry_length
//	[4:8]   name_offset (relative to entry start)
//	[8:12]  vector_length = 0
//	[12]    data_type = 'J'
//	[13]    flags
//	[14]    data_unit
//	[15]    data_variability
//	[16:20] data_offset (relative to entry start)
//	[20:28] value (int64 LE)
//	[28:]   name (null-terminated)
func buildHsperfdataFixture(counters map[string]int64) []byte {
	const headerSize = 16
	const fixedFieldsSize = 28 // bytes before name in each entry

	// First pass: calculate total size
	type entry struct {
		name  string
		value int64
	}
	var entries []entry
	for name, val := range counters {
		entries = append(entries, entry{name, val})
	}

	// Build entries sequentially
	var entryBlobs [][]byte
	for _, e := range entries {
		nameBytes := append([]byte(e.name), 0) // null-terminated
		entryLen := fixedFieldsSize + len(nameBytes)
		// align to 4 bytes
		if entryLen%4 != 0 {
			entryLen += 4 - entryLen%4
		}
		blob := make([]byte, entryLen)
		binary.LittleEndian.PutUint32(blob[0:4], uint32(entryLen))
		binary.LittleEndian.PutUint32(blob[4:8], uint32(fixedFieldsSize)) // name at end
		binary.LittleEndian.PutUint32(blob[8:12], 0)                       // vector_length
		blob[12] = 'J'                                                      // data_type: long
		blob[13] = 0                                                        // flags
		blob[14] = 0                                                        // data_unit
		blob[15] = 0                                                        // data_variability
		binary.LittleEndian.PutUint32(blob[16:20], uint32(20))             // data_offset: right after header fields
		binary.LittleEndian.PutUint64(blob[20:28], uint64(e.value))
		copy(blob[fixedFieldsSize:], nameBytes)
		entryBlobs = append(entryBlobs, blob)
	}

	totalSize := headerSize
	for _, b := range entryBlobs {
		totalSize += len(b)
	}

	data := make([]byte, totalSize)
	// The parser always reads the magic as big-endian first (see doParseHsperfdata).
	// To signal a little-endian file, write hsperfdataMagicLE in big-endian
	// byte order so the parser's BigEndian.Uint32 reads it as 0xC0C0FECA.
	binary.BigEndian.PutUint32(data[0:4], hsperfdataMagicLE)
	data[4] = 1 // byte_order = LE
	data[5] = 2 // major
	data[6] = 0 // minor
	data[7] = 0 // reserved
	binary.LittleEndian.PutUint32(data[8:12], uint32(headerSize))
	binary.LittleEndian.PutUint32(data[12:16], uint32(len(entries)))

	pos := headerSize
	for _, b := range entryBlobs {
		copy(data[pos:], b)
		pos += len(b)
	}
	return data
}

// TestDoParseHsperfdata_ReturnsCorrectCounters verifies that the pure parsing
// function (extracted from the old os.ReadFile-based parseHsperfdata as part of
// M-B) correctly returns counter values from a synthetic fixture (M-B fix).
func TestDoParseHsperfdata_ReturnsCorrectCounters(t *testing.T) {
	want := map[string]int64{
		"sun.gc.collector.0.invocations": 42,
		"sun.gc.collector.1.invocations": 7,
		"sun.os.hrt.frequency":           1000000000,
	}

	data := buildHsperfdataFixture(want)
	result := doParseHsperfdata(data)
	if result == nil {
		t.Fatal("doParseHsperfdata returned nil for valid fixture")
	}

	for name, wantVal := range want {
		gotVal, ok := result.Counters[name]
		if !ok {
			t.Errorf("counter %q missing from result", name)
			continue
		}
		if gotVal != wantVal {
			t.Errorf("counter %q = %d; want %d", name, gotVal, wantVal)
		}
	}
}

// TestDoParseHsperfdata_TooShort verifies a too-short blob returns nil.
func TestDoParseHsperfdata_TooShort(t *testing.T) {
	if got := doParseHsperfdata([]byte{0xCA, 0xFE}); got != nil {
		t.Errorf("doParseHsperfdata(<short>) = non-nil; want nil")
	}
}

// TestDoParseHsperfdata_BadMagic verifies an unrecognised magic returns nil.
func TestDoParseHsperfdata_BadMagic(t *testing.T) {
	buf := make([]byte, 64)
	buf[0] = 0xDE
	buf[1] = 0xAD
	buf[2] = 0xBE
	buf[3] = 0xEF
	if got := doParseHsperfdata(buf); got != nil {
		t.Errorf("doParseHsperfdata(<bad magic>) = non-nil; want nil")
	}
}
