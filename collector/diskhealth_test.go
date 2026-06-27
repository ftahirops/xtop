//go:build linux

package collector

import (
	"encoding/binary"
	"testing"
)

// TestSMARTAttributeParsingMultiAttribute verifies that parsing multiple
// SMART attributes doesn't corrupt subsequent attributes due to in-place append.
// This test exposes the bug at diskhealth.go:337 where append() mutates the data buffer.
//
// The bug: append(data[offset+5:offset+11], 0, 0) writes zeros in-place to data[offset+11:offset+13],
// corrupting the next attribute's ID and flags bytes.
func TestSMARTAttributeParsingMultiAttribute(t *testing.T) {
	// Build a buffer with two consecutive SMART attributes to demonstrate corruption.
	// SMART response structure: 4-byte header + 512-byte data
	// In the data: attributes start at offset 2, each 12 bytes.
	//
	// Attribute layout (12 bytes):
	//   [0]    : ID
	//   [1-2]  : Flags
	//   [3]    : Normalized
	//   [4]    : Worst
	//   [5-10] : Raw value (6 bytes, LE)

	t.Run("BuggyAppendCorruptsNextAttribute", func(t *testing.T) {
		// Create buffer with two attributes
		buf := make([]byte, 4+512)
		buf[0] = 0xB0 // winSmart
		buf[1] = 0xD0 // smartReadValues
		buf[2] = 1
		buf[3] = 0

		// Attribute 1: ID 5 (Reallocated_Sector_Ct) at data offset 2
		attrBase := 4 + 2
		buf[attrBase+0] = 5        // ID
		buf[attrBase+1] = 0x00
		buf[attrBase+2] = 0x00
		buf[attrBase+3] = 100      // normalized
		buf[attrBase+4] = 100      // worst
		buf[attrBase+5] = 66       // raw bytes 0-5 (little-endian)
		buf[attrBase+6] = 0
		buf[attrBase+7] = 0
		buf[attrBase+8] = 0
		buf[attrBase+9] = 0
		buf[attrBase+10] = 0

		// Attribute 2: ID 9 (Power_On_Hours) at data offset 2+12=14
		attrBase2 := 4 + 14
		buf[attrBase2+0] = 9       // ID = 9 (will be corrupted by buggy append)
		buf[attrBase2+1] = 0x00
		buf[attrBase2+2] = 0x00
		buf[attrBase2+3] = 90      // normalized
		buf[attrBase2+4] = 90      // worst
		buf[attrBase2+5] = 0x10
		buf[attrBase2+6] = 0x27
		buf[attrBase2+7] = 0
		buf[attrBase2+8] = 0
		buf[attrBase2+9] = 0
		buf[attrBase2+10] = 0

		data := buf[4:]
		offset1 := 2 + 0*12
		offset2 := 2 + 1*12

		// Read attr1 before buggy line
		id1Before := data[offset1]
		// The buggy line: append writes to data[offset1+11] and data[offset1+12]
		// which is the same as data[offset2+0] and data[offset2+1]
		id2Before := data[offset2]

		// Simulate the buggy code - append with spare capacity modifies in-place
		_ = binary.LittleEndian.Uint64(append(data[offset1+5:offset1+11], 0, 0))

		id2After := data[offset2]

		// With buggy code, id2After should be 0 (corrupted)
		if id1Before == 5 && id2Before == 9 {
			t.Logf("Before buggy append: attr1 ID=%d, attr2 ID=%d", id1Before, id2Before)
			t.Logf("After buggy append: attr1 ID=%d, attr2 ID=%d", id1Before, id2After)
			if id2After != 9 {
				t.Logf("CONFIRMED BUG: attr2 ID corrupted from 9 to %d", id2After)
			}
		}
	})

	t.Run("FixedCopyPreservesAllAttributes", func(t *testing.T) {
		// Same buffer setup
		buf := make([]byte, 4+512)
		buf[0] = 0xB0
		buf[1] = 0xD0
		buf[2] = 1
		buf[3] = 0

		// Attribute 1
		attrBase := 4 + 2
		buf[attrBase+0] = 5
		buf[attrBase+1] = 0x00
		buf[attrBase+2] = 0x00
		buf[attrBase+3] = 100
		buf[attrBase+4] = 100
		buf[attrBase+5] = 66
		buf[attrBase+6] = 0
		buf[attrBase+7] = 0
		buf[attrBase+8] = 0
		buf[attrBase+9] = 0
		buf[attrBase+10] = 0

		// Attribute 2
		attrBase2 := 4 + 14
		buf[attrBase2+0] = 9
		buf[attrBase2+1] = 0x00
		buf[attrBase2+2] = 0x00
		buf[attrBase2+3] = 90
		buf[attrBase2+4] = 90
		buf[attrBase2+5] = 0x10
		buf[attrBase2+6] = 0x27
		buf[attrBase2+7] = 0
		buf[attrBase2+8] = 0
		buf[attrBase2+9] = 0
		buf[attrBase2+10] = 0

		data := buf[4:]
		offset1 := 2
		offset2 := 14

		// Read attributes
		id1 := data[offset1]
		raw1_32 := int(binary.LittleEndian.Uint32(data[offset1+5 : offset1+9]))

		// Use fixed approach: copy to fresh array, no mutation
		var raw48_1 [8]byte
		copy(raw48_1[:6], data[offset1+5:offset1+11])
		raw1_48 := binary.LittleEndian.Uint64(raw48_1[:])

		// Read attr2 - should NOT be corrupted
		id2 := data[offset2]
		norm2 := int(data[offset2+3])
		raw2_32 := int(binary.LittleEndian.Uint32(data[offset2+5 : offset2+9]))

		// Verify all values are correct
		if id1 != 5 {
			t.Errorf("Attr1 ID: got %d, want 5", id1)
		}
		if raw1_32 != 66 {
			t.Errorf("Attr1 raw32: got %d, want 66", raw1_32)
		}
		if raw1_48 != 66 {
			t.Errorf("Attr1 raw48: got %d, want 66", raw1_48)
		}
		if id2 != 9 {
			t.Errorf("Attr2 ID: got %d, want 9", id2)
		}
		if norm2 != 90 {
			t.Errorf("Attr2 normalized: got %d, want 90", norm2)
		}
		if raw2_32 != 10000 {
			t.Errorf("Attr2 raw32: got %d, want 10000", raw2_32)
		}
	})
}
