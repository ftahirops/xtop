package collector

import (
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"

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

	info.Hostname, _ = os.Hostname()
	info.IPs = collectIPs()
	info.Arch = runtime.GOARCH

	// Kernel version
	var uts syscall.Utsname
	if syscall.Uname(&uts) == nil {
		info.Kernel = utsToString(uts.Release[:])
	}

	// OS name
	info.OS = detectOS()

	// CPU model
	info.CPUModel = detectCPUModel()

	// Virtualization + cloud detection
	info.Virtualization, info.CloudProvider = detectVirtAndCloud()

	return info
}

func utsToString(b []int8) string {
	var s []byte
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

func detectOS() string {
	data, err := util.ReadFileString("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			v = strings.Trim(v, "\"")
			return v
		}
	}
	return ""
}

func detectCPUModel() string {
	data, _ := util.ReadFileString("/proc/cpuinfo")
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
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

func detectVirtAndCloud() (virt, cloud string) {
	// 1. Container checks first
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Container (Docker)", ""
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "Container (Podman)", ""
	}
	cgroup, _ := util.ReadFileString("/proc/1/cgroup")
	if strings.Contains(cgroup, "/lxc/") {
		return "Container (LXC)", ""
	}
	if strings.Contains(cgroup, "/docker/") || strings.Contains(cgroup, "/docker-") {
		return "Container (Docker)", ""
	}

	// 2. DMI-based detection
	vendor, _ := util.ReadFileString("/sys/class/dmi/id/sys_vendor")
	vendor = strings.TrimSpace(vendor)
	product, _ := util.ReadFileString("/sys/class/dmi/id/product_name")
	product = strings.TrimSpace(product)
	biosVendor, _ := util.ReadFileString("/sys/class/dmi/id/bios_vendor")
	biosVendor = strings.TrimSpace(biosVendor)
	boardVendor, _ := util.ReadFileString("/sys/class/dmi/id/board_vendor")
	boardVendor = strings.TrimSpace(boardVendor)
	boardName, _ := util.ReadFileString("/sys/class/dmi/id/board_name")
	boardName = strings.TrimSpace(boardName)
	chassisAssetTag, _ := util.ReadFileString("/sys/class/dmi/id/chassis_asset_tag")
	chassisAssetTag = strings.TrimSpace(chassisAssetTag)
	chassisVendor, _ := util.ReadFileString("/sys/class/dmi/id/chassis_vendor")
	chassisVendor = strings.TrimSpace(chassisVendor)

	vl := strings.ToLower(vendor)
	pl := strings.ToLower(product)
	bl := strings.ToLower(biosVendor)
	bvl := strings.ToLower(boardVendor)
	bnl := strings.ToLower(boardName)
	cal := strings.ToLower(chassisAssetTag)
	cvl := strings.ToLower(chassisVendor)

	// Cloud provider detection (more specific → less specific)
	switch {
	// AWS: bios_vendor="Amazon EC2" or chassis_asset_tag starts with "i-"
	case strings.Contains(bl, "amazon") || strings.HasPrefix(cal, "i-") ||
		strings.Contains(vl, "amazon"):
		cloud = "AWS"
		if strings.Contains(pl, "metal") {
			virt = "Bare Metal (AWS)"
		} else {
			virt = "VM (KVM/AWS)"
		}
		return

	// Hetzner
	case strings.Contains(vl, "hetzner") || strings.Contains(cvl, "hetzner") ||
		strings.Contains(bvl, "hetzner"):
		cloud = "Hetzner"
		if strings.Contains(pl, "vserver") || strings.Contains(vl, "hetzner") {
			virt = "VM (KVM/Hetzner)"
		} else {
			virt = "Dedicated (Hetzner)"
		}
		return

	// DigitalOcean
	case strings.Contains(vl, "digitalocean") || strings.Contains(cvl, "digitalocean"):
		cloud = "DigitalOcean"
		virt = "VM (KVM/DigitalOcean)"
		return

	// Google Cloud
	case strings.Contains(vl, "google") || strings.Contains(pl, "google compute"):
		cloud = "GCP"
		virt = "VM (KVM/GCP)"
		return

	// Azure
	case (strings.Contains(vl, "microsoft") && strings.Contains(pl, "virtual")) ||
		strings.Contains(cal, "7783-7084-3265-9085-8269"):
		cloud = "Azure"
		virt = "VM (Hyper-V/Azure)"
		return

	// Vultr
	case strings.Contains(vl, "vultr") || strings.Contains(cvl, "vultr"):
		cloud = "Vultr"
		virt = "VM (KVM/Vultr)"
		return

	// Linode / Akamai
	case strings.Contains(vl, "linode") || strings.Contains(pl, "linode") ||
		strings.Contains(cvl, "linode"):
		cloud = "Linode"
		virt = "VM (KVM/Linode)"
		return

	// OVH
	case strings.Contains(vl, "ovh") || strings.Contains(cvl, "ovh"):
		cloud = "OVH"
		virt = "VM (KVM/OVH)"
		return

	// Oracle Cloud
	case strings.Contains(vl, "oracle") && strings.Contains(pl, "virtual"):
		cloud = "Oracle Cloud"
		virt = "VM (KVM/Oracle)"
		return

	// Scaleway
	case strings.Contains(vl, "scaleway") || strings.Contains(cvl, "scaleway"):
		cloud = "Scaleway"
		virt = "VM (KVM/Scaleway)"
		return

	// UpCloud
	case strings.Contains(vl, "upcloud"):
		cloud = "UpCloud"
		virt = "VM (KVM/UpCloud)"
		return
	}

	// Hypervisor detection (non-cloud or unrecognized cloud)
	switch {
	case strings.Contains(vl, "vmware"):
		virt = "VM (VMware ESXi)"
		return

	case strings.Contains(vl, "qemu") || strings.Contains(pl, "kvm") ||
		strings.Contains(pl, "standard pc"):
		// Check for Proxmox: QEMU + product contains "Standard PC" + cpu model
		// Proxmox uses QEMU/KVM — check for pve-manager or specific DMI
		if isProxmox() {
			virt = "VM (Proxmox/KVM)"
		} else {
			virt = "VM (KVM/QEMU)"
		}
		return

	case strings.Contains(vl, "xen") || strings.HasPrefix(pl, "hvm"):
		// AWS EC2 older instances use Xen with "HVM domU" product
		if pl == "hvm domu" && vl == "xen" {
			cloud = "AWS"
			virt = "VM (Xen/AWS)"
		} else {
			virt = "VM (Xen)"
		}
		return

	case strings.Contains(vl, "microsoft") && strings.Contains(pl, "virtual"):
		virt = "VM (Hyper-V)"
		return

	case strings.Contains(vl, "innotek") || strings.Contains(pl, "virtualbox"):
		virt = "VM (VirtualBox)"
		return

	case strings.Contains(vl, "parallels"):
		virt = "VM (Parallels)"
		return

	case strings.Contains(bnl, "bhyve"):
		virt = "VM (bhyve)"
		return
	}

	// 3. MAC address OUI-based detection (fallback)
	if mac := detectByMAC(); mac != "" {
		virt = mac
		return
	}

	// 4. Check hypervisor flag in cpuinfo
	cpuinfo, _ := util.ReadFileString("/proc/cpuinfo")
	if strings.Contains(cpuinfo, "hypervisor") {
		virt = "VM (unknown)"
		return
	}

	// 5. Check known hardware vendors for bare metal
	switch {
	case strings.Contains(vl, "dell"):
		virt = "Bare Metal (Dell)"
	case strings.Contains(vl, "hp") || strings.Contains(vl, "hewlett"):
		virt = "Bare Metal (HP)"
	case strings.Contains(vl, "supermicro"):
		virt = "Bare Metal (Supermicro)"
	case strings.Contains(vl, "lenovo"):
		virt = "Bare Metal (Lenovo)"
	case strings.Contains(vl, "intel"):
		virt = "Bare Metal (Intel)"
	case strings.Contains(vl, "gigabyte"):
		virt = "Bare Metal (Gigabyte)"
	case strings.Contains(vl, "asus"):
		virt = "Bare Metal (ASUS)"
	default:
		virt = "Bare Metal"
	}
	return
}

// isProxmox checks for Proxmox VE signatures.
func isProxmox() bool {
	// Proxmox sets specific SMBIOS data; also check for pve-manager
	product, _ := util.ReadFileString("/sys/class/dmi/id/product_serial")
	if strings.Contains(strings.ToLower(product), "proxmox") {
		return true
	}
	// Check /proc/version for pve kernel
	version, _ := util.ReadFileString("/proc/version")
	if strings.Contains(version, "pve") {
		return true
	}
	// Check if qemu-ga (QEMU Guest Agent for Proxmox) is running
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only check first 50 numeric dirs
		if e.Name()[0] < '1' || e.Name()[0] > '9' {
			continue
		}
		cmdline, _ := util.ReadFileString("/proc/" + e.Name() + "/comm")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline == "qemu-ga" || cmdline == "pvestatd" || cmdline == "pvedaemon" {
			return true
		}
	}
	return false
}

// detectByMAC checks network interface MAC address OUI prefixes.
func detectByMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if len(mac) < 8 {
			continue
		}
		prefix := strings.ToLower(mac[:8])
		switch prefix {
		case "52:54:00":
			return "VM (KVM/QEMU)"
		case "00:0c:29", "00:50:56":
			return "VM (VMware)"
		case "08:00:27":
			return "VM (VirtualBox)"
		case "00:16:3e":
			return "VM (Xen)"
		case "00:15:5d":
			return "VM (Hyper-V)"
		}
	}
	return ""
}
