package collector

import (
	"net"
	"os"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// SysInfoCollector collects hostname, IPs, and virtualization type once.
type SysInfoCollector struct {
	once   sync.Once
	cached *model.SysInfo
}

func (s *SysInfoCollector) Name() string { return "sysinfo" }

func (s *SysInfoCollector) Collect(snap *model.Snapshot) error {
	s.once.Do(func() {
		s.cached = collectSysInfo()
	})
	snap.SysInfo = s.cached
	return nil
}

func collectSysInfo() *model.SysInfo {
	info := &model.SysInfo{}

	// Hostname
	info.Hostname, _ = os.Hostname()

	// IPs: non-loopback addresses
	info.IPs = collectIPs()

	// Virtualization detection
	info.Virtualization = detectVirtualization()

	return info
}

func collectIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		// Skip virtual/container interfaces — only show real host IPs
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "cni") ||
			strings.HasPrefix(name, "flannel") ||
			strings.HasPrefix(name, "cali") ||
			strings.HasPrefix(name, "tunl") ||
			strings.HasPrefix(name, "weave") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ip.String())
			if len(ips) >= 3 {
				return ips
			}
		}
	}
	return ips
}

func detectVirtualization() string {
	// 1. Container checks first
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Container (Docker)"
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "Container (Podman)"
	}
	cgroup, _ := util.ReadFileString("/proc/1/cgroup")
	if strings.Contains(cgroup, "/lxc/") {
		return "Container (LXC)"
	}
	if strings.Contains(cgroup, "/docker/") || strings.Contains(cgroup, "/docker-") {
		return "Container (Docker)"
	}

	// 2. DMI-based detection (sys_vendor + product_name)
	vendor, _ := util.ReadFileString("/sys/class/dmi/id/sys_vendor")
	vendor = strings.TrimSpace(vendor)
	product, _ := util.ReadFileString("/sys/class/dmi/id/product_name")
	product = strings.TrimSpace(product)

	vendorLower := strings.ToLower(vendor)
	productLower := strings.ToLower(product)

	switch {
	case strings.Contains(vendorLower, "vmware"):
		return "VM (VMware)"
	case strings.Contains(vendorLower, "qemu") || strings.Contains(productLower, "kvm"):
		return "VM (KVM)"
	case strings.Contains(vendorLower, "xen"):
		return "VM (Xen)"
	case strings.Contains(vendorLower, "microsoft") && strings.Contains(productLower, "virtual"):
		return "VM (Hyper-V)"
	case strings.Contains(vendorLower, "innotek") || strings.Contains(productLower, "virtualbox"):
		return "VM (VirtualBox)"
	case strings.Contains(vendorLower, "parallels"):
		return "VM (Parallels)"
	case strings.Contains(vendorLower, "amazon") || strings.Contains(productLower, "hvm"):
		return "VM (AWS)"
	case strings.Contains(vendorLower, "google"):
		return "VM (GCE)"
	}

	// 3. Check hypervisor flag in cpuinfo
	cpuinfo, _ := util.ReadFileString("/proc/cpuinfo")
	if strings.Contains(cpuinfo, "hypervisor") {
		return "VM (unknown)"
	}

	return "Bare Metal"
}
