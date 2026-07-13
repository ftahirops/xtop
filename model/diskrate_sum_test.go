package model

import "testing"

// On LVM/dm hosts /proc/diskstats reports the SAME bytes at both the physical
// layer (sda) and the device-mapper layer (dm-0). Host-total sums must count
// each byte once: exclude dm-*/md* layers when a physical device is present,
// but fall back to summing everything when only virtual devices are visible.
func TestSumDiskThroughputExcludesDMLayer(t *testing.T) {
	disks := []DiskRate{
		{Name: "sda", ReadMBs: 1.5, WriteMBs: 8.3, ReadIOPS: 10, WriteIOPS: 2086},
		{Name: "dm-0", ReadMBs: 1.5, WriteMBs: 8.3, ReadIOPS: 10, WriteIOPS: 2126},
	}
	r, w := SumDiskThroughput(disks)
	if r != 1.5 || w != 8.3 {
		t.Fatalf("dm layer double-counted: got R=%.1f W=%.1f, want R=1.5 W=8.3", r, w)
	}
	ri, wi := SumDiskIOPS(disks)
	if ri != 10 || wi != 2086 {
		t.Fatalf("dm layer IOPS double-counted: got R=%.0f W=%.0f, want R=10 W=2086", ri, wi)
	}
}

func TestSumDiskThroughputDMOnlyFallback(t *testing.T) {
	disks := []DiskRate{
		{Name: "dm-0", ReadMBs: 2, WriteMBs: 4},
		{Name: "dm-1", ReadMBs: 1, WriteMBs: 1},
	}
	r, w := SumDiskThroughput(disks)
	if r != 3 || w != 5 {
		t.Fatalf("dm-only host must sum dm devices: got R=%.0f W=%.0f, want R=3 W=5", r, w)
	}
}

func TestSumDiskThroughputMultiplePhysical(t *testing.T) {
	disks := []DiskRate{
		{Name: "sda", WriteMBs: 4},
		{Name: "nvme0n1", WriteMBs: 6},
		{Name: "md0", WriteMBs: 10}, // raid layer over the two — skip
	}
	_, w := SumDiskThroughput(disks)
	if w != 10 {
		t.Fatalf("got W=%.0f, want 10 (sda+nvme, md layer excluded)", w)
	}
}
