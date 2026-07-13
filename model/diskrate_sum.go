package model

import "strings"

// isLayeredBlockDevice reports whether a block device is a virtual layer
// (device-mapper / md-raid) that re-reports IO already counted at the physical
// device beneath it in /proc/diskstats.
func isLayeredBlockDevice(name string) bool {
	return strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "md")
}

// sumDiskRates sums pick() across DiskRates counting each byte once: layered
// devices (dm-*/md*) are excluded when at least one physical device is present,
// since LVM/RAID hosts report the same IO at both layers. When only layered
// devices are visible (e.g. restricted views), they are summed as-is.
func sumDiskRates(disks []DiskRate, pick func(*DiskRate) (float64, float64)) (a, b float64) {
	hasPhysical := false
	for i := range disks {
		if !isLayeredBlockDevice(disks[i].Name) {
			hasPhysical = true
			break
		}
	}
	for i := range disks {
		if hasPhysical && isLayeredBlockDevice(disks[i].Name) {
			continue
		}
		x, y := pick(&disks[i])
		a += x
		b += y
	}
	return a, b
}

// SumDiskThroughput returns host-total read/write MB/s without double-counting
// LVM/RAID layers.
func SumDiskThroughput(disks []DiskRate) (readMBs, writeMBs float64) {
	return sumDiskRates(disks, func(d *DiskRate) (float64, float64) { return d.ReadMBs, d.WriteMBs })
}

// SumDiskIOPS returns host-total read/write IOPS without double-counting
// LVM/RAID layers.
func SumDiskIOPS(disks []DiskRate) (readIOPS, writeIOPS float64) {
	return sumDiskRates(disks, func(d *DiskRate) (float64, float64) { return d.ReadIOPS, d.WriteIOPS })
}
