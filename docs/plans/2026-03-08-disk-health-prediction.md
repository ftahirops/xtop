# Disk Health & Life Prediction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Show disk wear, age, and failure prediction at the top of the IO page using hardware-reported data via direct kernel ioctls (no external dependencies).

**Architecture:** Layered collector reads NVMe health log via ioctl, SATA SMART attributes via HDIO ioctl, falls back to smartctl. Extended model adds available_spare, critical_warning, media_errors, data_units_written, disk_type, and estimated remaining life. IO page gets a prominent DISK HEALTH section at the top with life bar and failure prediction.

**Tech Stack:** Go syscall/unsafe for ioctls, existing Bubbletea/lipgloss UI

---

### Task 1: Extend model/smart.go with health fields

**Files:**
- Modify: `model/smart.go`

Add fields: DiskType, AvailableSpare, AvailableSpareThreshold, CriticalWarning, MediaErrors, DataUnitsWritten, UnsafeShutdowns, EstLifeDays, TotalWrittenBytes, WriteRateBytesPerDay.

### Task 2: Create collector/diskhealth.go — NVMe ioctl reader

**Files:**
- Create: `collector/diskhealth.go`

Implement NVMe SMART log reading via NVME_IOCTL_ADMIN_CMD (Get Log Page, log ID 0x02). Parse the 512-byte health log into model fields. Discover NVMe devices from /sys/class/nvme/ and open /dev/nvme0 character device.

### Task 3: Add SATA SMART ioctl reader to diskhealth.go

Add HDIO_DRIVE_CMD ioctl reader for SATA drives. Send WIN_SMART/SMART_READ_VALUES command, parse 30 attribute entries. Extract attributes 5, 9, 177, 194, 197, 231, 233, 241.

### Task 4: Integrate into existing SMARTCollector

**Files:**
- Modify: `collector/smart.go`

Change Get() to try ioctl-based collection first, fall back to smartctl. Merge results, compute estimated life from write rate + wear level.

### Task 5: Redesign IO page DISK HEALTH section

**Files:**
- Modify: `ui/page_io.go`

Move SMART section to top of page, rename to DISK HEALTH. Add life gauge bar, disk type label, total written, estimated remaining life. Color-code by severity.

### Task 6: Add RCA evidence for disk health

**Files:**
- Modify: `engine/rca.go`

Add evidence: io.disk.wear (wear level critical), io.disk.spare (available spare low), io.disk.media_errors.

### Task 7: Build, test, deploy

Build v0.21.9, deploy, create deb, commit, push, release.
