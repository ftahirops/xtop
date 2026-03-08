//go:build linux

package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// ProxmoxCollector gathers Proxmox VE host and VM metrics.
type ProxmoxCollector struct {
	detected     bool
	checkedOnce  bool
	prevVMCPU    map[int]uint64 // VMID → previous CPU usage (µs)
	prevVMIO     map[int][2]uint64 // VMID → [read, write] bytes
	prevNetBytes map[string][2]uint64 // iface → [rx, tx]
	prevTime     time.Time
}

func (p *ProxmoxCollector) Name() string { return "proxmox" }

func (p *ProxmoxCollector) Collect(snap *model.Snapshot) error {
	if !p.checkedOnce {
		p.checkedOnce = true
		if _, err := os.Stat("/etc/pve"); err == nil {
			p.detected = true
		}
	}
	if !p.detected {
		return nil
	}

	if snap.Global.Proxmox == nil {
		snap.Global.Proxmox = &model.ProxmoxMetrics{}
	}
	pve := snap.Global.Proxmox
	pve.IsProxmoxHost = true

	// Node name
	if h, err := os.Hostname(); err == nil {
		pve.NodeName = h
	}

	// PVE version (cached after first read)
	if pve.PVEVersion == "" {
		pve.PVEVersion = readPVEVersion()
	}

	// Parse VM configs
	vms := p.parseVMConfigs()

	// Match running KVM processes
	p.matchRunningVMs(vms)

	// Collect live metrics
	now := time.Now()
	dt := now.Sub(p.prevTime)
	if dt < 100*time.Millisecond {
		dt = 3 * time.Second
	}

	for i := range vms {
		if vms[i].PID > 0 {
			p.collectVMLive(&vms[i], dt)
		}
	}

	p.prevTime = now
	pve.VMs = vms

	// Storage
	pve.Storage = p.parseStorage()

	return nil
}

// parseVMConfigs reads /etc/pve/qemu-server/*.conf
func (p *ProxmoxCollector) parseVMConfigs() []model.ProxmoxVM {
	matches, _ := filepath.Glob("/etc/pve/qemu-server/*.conf")
	var vms []model.ProxmoxVM

	for _, path := range matches {
		base := filepath.Base(path)
		vmidStr := strings.TrimSuffix(base, ".conf")
		vmid, err := strconv.Atoi(vmidStr)
		if err != nil {
			continue
		}

		vm := model.ProxmoxVM{
			VMID:   vmid,
			Status: "stopped",
		}

		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		inSnapshot := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Skip [snapshot] sections — they duplicate disk/net keys
			if strings.HasPrefix(line, "[") {
				inSnapshot = true
				continue
			}
			if inSnapshot {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			switch key {
			case "name":
				vm.Name = val
			case "cores":
				vm.CoresAlloc, _ = strconv.Atoi(val)
			case "sockets":
				vm.SocketsAlloc, _ = strconv.Atoi(val)
			case "memory":
				vm.MemAllocMB, _ = strconv.Atoi(val)
			case "balloon":
				bval, _ := strconv.Atoi(val)
				if bval > 0 {
					vm.BalloonOn = true
					vm.BalloonMinMB = bval
				}
				// balloon: 0 means disabled explicitly
			default:
				// Disk configs: scsi0, virtio0, ide2, sata0, etc.
				if isProxmoxDiskKey(key) {
					dc := parseProxmoxDisk(key, val)
					if dc.Bus != "" {
						vm.DiskConfigs = append(vm.DiskConfigs, dc)
					}
				}
				// Network configs: net0, net1, etc.
				if strings.HasPrefix(key, "net") {
					nc := parseProxmoxNet(key, val)
					if nc.ID != "" {
						vm.NetConfigs = append(vm.NetConfigs, nc)
					}
				}
			}
		}
		f.Close()

		if vm.Name == "" {
			vm.Name = fmt.Sprintf("VM %d", vmid)
		}

		vms = append(vms, vm)
	}
	return vms
}

var proxmoxDiskRE = regexp.MustCompile(`^(scsi|virtio|ide|sata|efidisk)\d+$`)

func isProxmoxDiskKey(key string) bool {
	return proxmoxDiskRE.MatchString(key)
}

func parseProxmoxDisk(key, val string) model.ProxmoxDiskConf {
	dc := model.ProxmoxDiskConf{Bus: key}
	// val format: "local-lvm:vm-100-disk-0,size=110G" or "none,media=cdrom"
	parts := strings.Split(val, ",")
	if len(parts) > 0 {
		dc.Path = parts[0]
	}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "size":
			sizeStr := strings.TrimRight(kv[1], "GgTtMm")
			sz, _ := strconv.Atoi(sizeStr)
			if strings.HasSuffix(strings.ToUpper(kv[1]), "T") {
				sz *= 1024
			}
			dc.SizeGB = sz
		case "cache":
			dc.Cache = kv[1]
		}
	}
	return dc
}

func parseProxmoxNet(key, val string) model.ProxmoxNetConf {
	nc := model.ProxmoxNetConf{ID: key}
	// val format: "virtio=00:50:56:00:81:63,bridge=vmbr0,tag=100"
	parts := strings.Split(val, ",")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "bridge":
			nc.Bridge = kv[1]
		case "tag":
			nc.Tag, _ = strconv.Atoi(kv[1])
		default:
			// Model=MAC pattern: "virtio=00:50:56:00:81:63"
			if looksLikeMAC(kv[1]) {
				nc.Model = kv[0]
				nc.MAC = kv[1]
			}
		}
	}
	return nc
}

func looksLikeMAC(s string) bool {
	return len(s) == 17 && strings.Count(s, ":") == 5
}

// matchRunningVMs finds KVM PIDs and matches them to VMs
func (p *ProxmoxCollector) matchRunningVMs(vms []model.ProxmoxVM) {
	// Build VMID→index map
	vmIdx := make(map[int]int)
	for i, vm := range vms {
		vmIdx[vm.VMID] = i
	}

	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, cmdPath := range procs {
		data, err := os.ReadFile(cmdPath)
		if err != nil {
			continue
		}
		cmdline := string(data)
		if !strings.Contains(cmdline, "/usr/bin/kvm") && !strings.Contains(cmdline, "qemu-system") {
			continue
		}

		// Extract -id XXX
		args := strings.Split(cmdline, "\x00")
		for j, arg := range args {
			if arg == "-id" && j+1 < len(args) {
				vmid, err := strconv.Atoi(args[j+1])
				if err != nil {
					continue
				}
				if idx, ok := vmIdx[vmid]; ok {
					// Extract PID from path
					pidStr := strings.TrimPrefix(filepath.Dir(cmdPath), "/proc/")
					pid, _ := strconv.Atoi(pidStr)
					vms[idx].PID = pid
					vms[idx].Status = "running"

					// Get uptime from process start time
					if stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
						s := string(stat)
						ci := strings.LastIndex(s, ")")
						if ci > 0 && ci+2 < len(s) {
							fields := strings.Fields(s[ci+2:])
							if len(fields) > 19 {
								startTicks, _ := strconv.ParseUint(fields[19], 10, 64)
								if startTicks > 0 {
									bootTime := readBootTimeFloat()
									if bootTime > 0 {
										startSec := bootTime + float64(startTicks)/100
										vms[idx].UptimeSec = int64(float64(time.Now().Unix()) - startSec)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func readBootTimeFloat() float64 {
	lines, err := util.ReadFileLines("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "btime ") {
			v, _ := strconv.ParseFloat(strings.Fields(line)[1], 64)
			return v
		}
	}
	return 0
}

// collectVMLive gathers live CPU/mem/IO for a running VM
func (p *ProxmoxCollector) collectVMLive(vm *model.ProxmoxVM, dt time.Duration) {
	if p.prevVMCPU == nil {
		p.prevVMCPU = make(map[int]uint64)
		p.prevVMIO = make(map[int][2]uint64)
		p.prevNetBytes = make(map[string][2]uint64)
	}

	// Memory from /proc/PID/status
	if status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", vm.PID)); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.Atoi(fields[1])
					vm.MemUsedMB = kb / 1024
				}
			}
		}
	}

	// Balloon memory from cgroup memory.current (actual memory assigned after ballooning)
	scope := fmt.Sprintf("%d.scope", vm.VMID)
	if vm.BalloonOn {
		vm.MemBalloonMB = readCgroupMemCurrent(scope)
	}

	// CPU from cgroup
	cpuUsage := readCgroupCPU(scope)
	if cpuUsage > 0 {
		prev := p.prevVMCPU[vm.VMID]
		if prev > 0 && cpuUsage >= prev {
			delta := cpuUsage - prev
			vm.CPUPct = float64(delta) / dt.Seconds() / 1e6 * 100 // µs → pct
		}
		p.prevVMCPU[vm.VMID] = cpuUsage
	}

	// IO from cgroup
	ioR, ioW := readCgroupIO(scope)
	prevIO := p.prevVMIO[vm.VMID]
	if prevIO[0] > 0 {
		if ioR >= prevIO[0] {
			vm.IOReadMBs = float64(ioR-prevIO[0]) / dt.Seconds() / (1024 * 1024)
		}
		if ioW >= prevIO[1] {
			vm.IOWriteMBs = float64(ioW-prevIO[1]) / dt.Seconds() / (1024 * 1024)
		}
	}
	p.prevVMIO[vm.VMID] = [2]uint64{ioR, ioW}

	// Network from /proc/net/dev (tap interfaces)
	tapName := fmt.Sprintf("tap%di0", vm.VMID)
	rxBytes, txBytes := readTapStats(tapName)
	prevNet := p.prevNetBytes[tapName]
	if prevNet[0] > 0 {
		if rxBytes >= prevNet[0] {
			vm.NetRxMBs = float64(rxBytes-prevNet[0]) / dt.Seconds() / (1024 * 1024)
		}
		if txBytes >= prevNet[1] {
			vm.NetTxMBs = float64(txBytes-prevNet[1]) / dt.Seconds() / (1024 * 1024)
		}
	}
	p.prevNetBytes[tapName] = [2]uint64{rxBytes, txBytes}
}

func readCgroupCPU(scope string) uint64 {
	// Try cgroup v2 first
	paths := []string{
		fmt.Sprintf("/sys/fs/cgroup/qemu.slice/%s/cpu.stat", scope),
		fmt.Sprintf("/sys/fs/cgroup/machine.slice/qemu-%s/cpu.stat", scope),
		fmt.Sprintf("/sys/fs/cgroup/machine.slice/%s/cpu.stat", scope),
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "usage_usec ") {
				v, _ := strconv.ParseUint(strings.Fields(line)[1], 10, 64)
				return v
			}
		}
	}
	return 0
}

func readCgroupMemCurrent(scope string) int {
	paths := []string{
		fmt.Sprintf("/sys/fs/cgroup/qemu.slice/%s/memory.current", scope),
		fmt.Sprintf("/sys/fs/cgroup/machine.slice/qemu-%s/memory.current", scope),
		fmt.Sprintf("/sys/fs/cgroup/machine.slice/%s/memory.current", scope),
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if v > 0 {
			return int(v / (1024 * 1024)) // bytes → MB
		}
	}
	return 0
}

func readCgroupIO(scope string) (uint64, uint64) {
	paths := []string{
		fmt.Sprintf("/sys/fs/cgroup/qemu.slice/%s/io.stat", scope),
		fmt.Sprintf("/sys/fs/cgroup/machine.slice/qemu-%s/io.stat", scope),
		fmt.Sprintf("/sys/fs/cgroup/machine.slice/%s/io.stat", scope),
	}
	var totalR, totalW uint64
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "rbytes=") {
					v, _ := strconv.ParseUint(strings.TrimPrefix(f, "rbytes="), 10, 64)
					totalR += v
				}
				if strings.HasPrefix(f, "wbytes=") {
					v, _ := strconv.ParseUint(strings.TrimPrefix(f, "wbytes="), 10, 64)
					totalW += v
				}
			}
		}
		return totalR, totalW
	}
	return 0, 0
}

func readTapStats(tapName string) (uint64, uint64) {
	lines, err := util.ReadFileLines("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range lines {
		if !strings.Contains(line, tapName+":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		return rx, tx
	}
	return 0, 0
}

// parseStorage reads /etc/pve/storage.cfg and gets usage via statvfs
func (p *ProxmoxCollector) parseStorage() []model.ProxmoxStorage {
	data, err := os.ReadFile("/etc/pve/storage.cfg")
	if err != nil {
		return nil
	}

	var storages []model.ProxmoxStorage
	var current *model.ProxmoxStorage

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// New storage block: "type: name"
		if !strings.HasPrefix(line, "\t") && strings.Contains(line, ":") {
			if current != nil {
				p.fillStorageUsage(current)
				storages = append(storages, *current)
			}
			parts := strings.SplitN(line, ":", 2)
			current = &model.ProxmoxStorage{
				Type: strings.TrimSpace(parts[0]),
				Name: strings.TrimSpace(parts[1]),
			}
			continue
		}

		if current != nil {
			kv := strings.SplitN(strings.TrimSpace(line), " ", 2)
			if len(kv) == 2 {
				switch strings.TrimSpace(kv[0]) {
				case "path":
					current.Path = strings.TrimSpace(kv[1])
				case "vgname":
					current.Path = "VG:" + strings.TrimSpace(kv[1])
				case "thinpool":
					current.Path += "/" + strings.TrimSpace(kv[1])
				case "pool":
					current.Path = "zpool:" + strings.TrimSpace(kv[1])
				}
			}
		}
	}
	if current != nil {
		p.fillStorageUsage(current)
		storages = append(storages, *current)
	}

	return storages
}

func (p *ProxmoxCollector) fillStorageUsage(s *model.ProxmoxStorage) {
	switch s.Type {
	case "lvmthin":
		// For LVM thin pools, try to read from lvs
		// Fallback: check mounted filesystem
		if s.Path != "" {
			p.statvfsStorage(s, "/")
		}
	case "dir":
		if s.Path != "" {
			p.statvfsStorage(s, s.Path)
		}
	case "nfs":
		if s.Path != "" {
			p.statvfsStorage(s, s.Path)
		}
	}
}

func (p *ProxmoxCollector) statvfsStorage(s *model.ProxmoxStorage, path string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return
	}
	s.TotalGB = float64(stat.Blocks*uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	s.AvailGB = float64(stat.Bavail*uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	s.UsedGB = s.TotalGB - s.AvailGB
	if s.TotalGB > 0 {
		s.UsedPct = s.UsedGB / s.TotalGB * 100
	}
}

// readPVEVersion gets PVE version from /usr/bin/pveversion script or proxmox-ve package.
func readPVEVersion() string {
	// Method 1: parse pveversion script for its embedded version
	if data, err := os.ReadFile("/usr/share/perl5/PVE/pvecfg.pm"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			// looks for: my $version = "8.x.y";
			if strings.Contains(line, "version") && strings.Contains(line, "\"") {
				i := strings.Index(line, "\"")
				j := strings.LastIndex(line, "\"")
				if i >= 0 && j > i {
					return line[i+1 : j]
				}
			}
		}
	}
	// Method 2: read proxmox-ve package version from dpkg info
	if data, err := os.ReadFile("/var/lib/dpkg/info/proxmox-ve.list"); err == nil {
		_ = data // file exists means proxmox-ve is installed
		// Parse just the proxmox-ve block from dpkg status
		if f, err := os.Open("/var/lib/dpkg/status"); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 256*1024)
			inBlock := false
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					inBlock = false
					continue
				}
				if line == "Package: proxmox-ve" {
					inBlock = true
					continue
				}
				if inBlock && strings.HasPrefix(line, "Version: ") {
					return strings.TrimPrefix(line, "Version: ")
				}
			}
		}
	}
	return ""
}
