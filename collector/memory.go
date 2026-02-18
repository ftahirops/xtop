package collector

import (
	"fmt"
	"strings"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// MemoryCollector reads /proc/meminfo and /proc/vmstat.
type MemoryCollector struct{}

func (m *MemoryCollector) Name() string { return "memory" }

func (m *MemoryCollector) Collect(snap *model.Snapshot) error {
	if err := m.collectMeminfo(snap); err != nil {
		return err
	}
	return m.collectVmstat(snap)
}

func (m *MemoryCollector) collectMeminfo(snap *model.Snapshot) error {
	kv, err := util.ParseKeyValueFile("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("read /proc/meminfo: %w", err)
	}

	mem := &snap.Global.Memory
	mem.Total = parseKB(kv["MemTotal"])
	mem.Free = parseKB(kv["MemFree"])
	mem.Available = parseKB(kv["MemAvailable"])
	mem.Buffers = parseKB(kv["Buffers"])
	mem.Cached = parseKB(kv["Cached"])
	mem.SwapTotal = parseKB(kv["SwapTotal"])
	mem.SwapFree = parseKB(kv["SwapFree"])
	mem.SwapUsed = mem.SwapTotal - mem.SwapFree
	mem.SwapCached = parseKB(kv["SwapCached"])
	mem.Dirty = parseKB(kv["Dirty"])
	mem.Writeback = parseKB(kv["Writeback"])
	mem.Slab = parseKB(kv["Slab"])
	mem.SReclaimable = parseKB(kv["SReclaimable"])
	mem.SUnreclaim = parseKB(kv["SUnreclaim"])
	mem.AnonPages = parseKB(kv["AnonPages"])
	mem.Mapped = parseKB(kv["Mapped"])
	mem.Shmem = parseKB(kv["Shmem"])
	mem.KernelStack = parseKB(kv["KernelStack"])
	mem.PageTables = parseKB(kv["PageTables"])
	mem.Bounce = parseKB(kv["Bounce"])
	mem.HugePages_Total = util.ParseUint64(kv["HugePages_Total"])
	mem.HugePages_Free = util.ParseUint64(kv["HugePages_Free"])
	mem.HugepageSize = parseKB(kv["Hugepagesize"])
	mem.DirectMap4k = parseKB(kv["DirectMap4k"])
	mem.DirectMap2M = parseKB(kv["DirectMap2M"])
	mem.DirectMap1G = parseKB(kv["DirectMap1G"])
	mem.Mlocked = parseKB(kv["Mlocked"])
	mem.Active = parseKB(kv["Active"])
	mem.Inactive = parseKB(kv["Inactive"])
	mem.ActiveAnon = parseKB(kv["Active(anon)"])
	mem.InactiveAnon = parseKB(kv["Inactive(anon)"])
	mem.ActiveFile = parseKB(kv["Active(file)"])
	mem.InactiveFile = parseKB(kv["Inactive(file)"])
	mem.Unevictable = parseKB(kv["Unevictable"])
	mem.VmallocTotal = parseKB(kv["VmallocTotal"])
	mem.VmallocUsed = parseKB(kv["VmallocUsed"])
	return nil
}

// parseKB parses a meminfo value like "1234 kB" and returns bytes.
func parseKB(s string) uint64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " kB")
	s = strings.TrimSuffix(s, "kB")
	s = strings.TrimSpace(s)
	return util.ParseUint64(s) * 1024
}

func (m *MemoryCollector) collectVmstat(snap *model.Snapshot) error {
	kv, err := util.ParseKeyValueFile("/proc/vmstat")
	if err != nil {
		return fmt.Errorf("read /proc/vmstat: %w", err)
	}

	vm := &snap.Global.VMStat
	vm.PgFault = util.ParseUint64(kv["pgfault"])
	vm.PgMajFault = util.ParseUint64(kv["pgmajfault"])
	vm.PgPgIn = util.ParseUint64(kv["pgpgin"])
	vm.PgPgOut = util.ParseUint64(kv["pgpgout"])
	vm.PswpIn = util.ParseUint64(kv["pswpin"])
	vm.PswpOut = util.ParseUint64(kv["pswpout"])
	vm.PgStealDirect = util.ParseUint64(kv["pgsteal_direct"])
	vm.PgStealKswapd = util.ParseUint64(kv["pgsteal_kswapd"])
	vm.PgScanDirect = util.ParseUint64(kv["pgscan_direct"])
	vm.PgScanKswapd = util.ParseUint64(kv["pgscan_kswapd"])
	vm.AllocStall = util.ParseUint64(kv["allocstall_normal"]) + util.ParseUint64(kv["allocstall_movable"])
	vm.CompactStall = util.ParseUint64(kv["compact_stall"])
	vm.OOMKill = util.ParseUint64(kv["oom_kill"])
	vm.NrDirtied = util.ParseUint64(kv["nr_dirtied"])
	vm.NrWritten = util.ParseUint64(kv["nr_written"])
	vm.ThpFaultAlloc = util.ParseUint64(kv["thp_fault_alloc"])
	vm.ThpCollapseAlloc = util.ParseUint64(kv["thp_collapse_alloc"])
	return nil
}
