//go:build linux

package cgroup

import (
	"testing"

	"github.com/ftahirops/xtop/model"
)

// On LVM hosts cgroup io.stat lists the SAME bytes at both the device-mapper
// row (e.g. 252:0) and the physical row (8:0). Summing all rows doubled every
// cgroup's IO (and the Top-writer attribution built on it). Layered rows must
// be skipped when identified.
func TestSumV2IOSkipsDeviceMapperRows(t *testing.T) {
	lines := []string{
		"8:0 rbytes=1048576 wbytes=8388608 rios=10 wios=2086 dbytes=0 dios=0",
		"252:0 rbytes=1048576 wbytes=8388608 rios=10 wios=2126 dbytes=0 dios=0",
	}
	isLayered := func(majmin string) bool { return majmin == "252:0" }

	var cg model.CgroupMetrics
	sumV2IOLines(lines, isLayered, &cg)

	if cg.IORBytes != 1048576 || cg.IOWBytes != 8388608 {
		t.Fatalf("dm row double-counted: R=%d W=%d, want R=1048576 W=8388608", cg.IORBytes, cg.IOWBytes)
	}
	if cg.IOWIOs != 2086 {
		t.Fatalf("dm row IOs double-counted: wios=%d, want 2086", cg.IOWIOs)
	}
}

func TestSumV2IOKeepsAllWhenNoneLayered(t *testing.T) {
	lines := []string{
		"8:0 rbytes=100 wbytes=200 rios=1 wios=2",
		"8:16 rbytes=300 wbytes=400 rios=3 wios=4",
	}
	var cg model.CgroupMetrics
	sumV2IOLines(lines, func(string) bool { return false }, &cg)
	if cg.IORBytes != 400 || cg.IOWBytes != 600 {
		t.Fatalf("independent disks must both count: R=%d W=%d", cg.IORBytes, cg.IOWBytes)
	}
}
