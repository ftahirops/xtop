package runtime

import (
	"bytes"
	"encoding/binary"
	"os"
)

// hsperfdataHeader is the binary header of a JVM hsperfdata file.
type hsperfdataHeader struct {
	Magic       uint32
	ByteOrder   byte // 0 = big-endian, 1 = little-endian
	MajorVer    byte
	MinorVer    byte
	_           byte // reserved
	EntryOffset int32
	NumEntries  int32
}

// hsperfdataEntry represents a single counter entry.
type hsperfdataEntry struct {
	Name  string
	Value int64
}

// JVMPerfData holds parsed JVM performance counters.
type JVMPerfData struct {
	Counters map[string]int64
}

const (
	hsperfdataMagicBE = 0xCAFEC0C0
	hsperfdataMagicLE = 0xC0C0FECA
)

// parseHsperfdata reads and parses a JVM hsperfdata binary file.
// Returns nil if the file cannot be parsed (not a valid hsperfdata file).
func parseHsperfdata(path string) *JVMPerfData {
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 32 {
		return nil
	}

	// Detect endianness from magic
	magic := binary.BigEndian.Uint32(data[:4])
	var order binary.ByteOrder
	switch magic {
	case hsperfdataMagicBE:
		order = binary.BigEndian
	case hsperfdataMagicLE:
		order = binary.LittleEndian
	default:
		// Try little-endian interpretation
		magic = binary.LittleEndian.Uint32(data[:4])
		if magic == hsperfdataMagicBE {
			order = binary.LittleEndian
		} else {
			return nil // unrecognized format
		}
	}

	// Parse header
	// Skip magic (4) + byte_order (1) + major (1) + minor (1) + reserved (1) = 8 bytes
	// Then: entry_offset (4), num_entries (4)
	if len(data) < 16 {
		return nil
	}

	entryOffset := int(int32(order.Uint32(data[8:12])))
	numEntries := int(int32(order.Uint32(data[12:16])))

	if entryOffset < 16 || entryOffset >= len(data) || numEntries <= 0 || numEntries > 10000 {
		return nil
	}

	result := &JVMPerfData{
		Counters: make(map[string]int64),
	}

	pos := entryOffset
	for i := 0; i < numEntries && pos < len(data); i++ {
		entry, newPos := parseHsperfdataEntry(data, pos, order)
		if entry == nil || newPos <= pos {
			break
		}
		result.Counters[entry.Name] = entry.Value
		pos = newPos
	}

	return result
}

// parseHsperfdataEntry parses a single entry at the given offset.
// Entry format:
//   entry_length (4 bytes)
//   name_offset (4 bytes) - relative to entry start
//   vector_length (4 bytes)
//   data_type (1 byte): 'B'=byte, 'J'=long, 'I'=int
//   flags (1 byte)
//   data_unit (1 byte)
//   data_variability (1 byte)
//   data_offset (4 bytes) - relative to entry start
func parseHsperfdataEntry(data []byte, offset int, order binary.ByteOrder) (*hsperfdataEntry, int) {
	if offset+20 > len(data) {
		return nil, offset
	}

	entryLen := int(int32(order.Uint32(data[offset : offset+4])))
	if entryLen <= 0 || offset+entryLen > len(data) {
		return nil, offset
	}

	nameOffset := int(int32(order.Uint32(data[offset+4 : offset+8])))
	dataType := data[offset+12]
	dataOffset := int(int32(order.Uint32(data[offset+16 : offset+20])))

	// Extract name (null-terminated string)
	nameStart := offset + nameOffset
	if nameStart < 0 || nameStart >= len(data) {
		return nil, offset + entryLen
	}
	nameEnd := bytes.IndexByte(data[nameStart:], 0)
	if nameEnd < 0 {
		return nil, offset + entryLen
	}
	name := string(data[nameStart : nameStart+nameEnd])

	// Extract value based on data type
	valStart := offset + dataOffset
	if valStart < 0 || valStart >= len(data) {
		return nil, offset + entryLen
	}

	var value int64
	switch dataType {
	case 'J': // long (8 bytes)
		if valStart+8 <= len(data) {
			value = int64(order.Uint64(data[valStart : valStart+8]))
		}
	case 'I': // int (4 bytes)
		if valStart+4 <= len(data) {
			value = int64(int32(order.Uint32(data[valStart : valStart+4])))
		}
	case 'B': // byte / string — skip (we only care about numeric counters)
		return nil, offset + entryLen
	default:
		return nil, offset + entryLen
	}

	return &hsperfdataEntry{Name: name, Value: value}, offset + entryLen
}

// getJVMCounter returns a counter value, or 0 if not found.
func (p *JVMPerfData) getCounter(name string) int64 {
	if p == nil {
		return 0
	}
	return p.Counters[name]
}

// getJVMHeapUsedBytes sums all space.used counters across all generations.
func (p *JVMPerfData) getHeapUsedBytes() int64 {
	if p == nil {
		return 0
	}
	var total int64
	for name, val := range p.Counters {
		if len(name) > 0 && val > 0 {
			// Pattern: sun.gc.generation.N.space.M.used
			if matchGlob(name, "sun.gc.generation.*.space.*.used") {
				total += val
			}
		}
	}
	return total
}

// getJVMHeapCapacityBytes sums all space.capacity counters.
func (p *JVMPerfData) getHeapCapacityBytes() int64 {
	if p == nil {
		return 0
	}
	var total int64
	for name, val := range p.Counters {
		if val > 0 && matchGlob(name, "sun.gc.generation.*.space.*.capacity") {
			total += val
		}
	}
	return total
}

// matchGlob does a simple dot-separated glob match where * matches one segment.
func matchGlob(s, pattern string) bool {
	sp := splitDot(s)
	pp := splitDot(pattern)
	if len(sp) != len(pp) {
		return false
	}
	for i := range pp {
		if pp[i] != "*" && pp[i] != sp[i] {
			return false
		}
	}
	return true
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return parts
}
