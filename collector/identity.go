package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/util"
)

// IdentityCollector resolves process PIDs to application identities.
// It caches identities per PID lifetime (cmdline/exe don't change).
type IdentityCollector struct {
	cache map[int]model.AppIdentity
	mu    sync.Mutex
}

func (c *IdentityCollector) Name() string { return "identity" }

func (c *IdentityCollector) Collect(snap *model.Snapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cache == nil {
		c.cache = make(map[int]model.AppIdentity)
	}

	// Scan /proc for all PIDs
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil // non-fatal
	}

	alive := make(map[int]bool)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		alive[pid] = true

		// Skip if already cached
		if _, ok := c.cache[pid]; ok {
			continue
		}

		// Resolve identity for new PID
		id := c.resolveIdentity(pid)
		if id.Comm == "" {
			continue // process likely exited during scan
		}
		c.cache[pid] = id
	}

	// Evict dead PIDs
	for pid := range c.cache {
		if !alive[pid] {
			delete(c.cache, pid)
		}
	}

	// Populate snapshot
	snap.Global.AppIdentities = make(map[int]model.AppIdentity, len(c.cache))
	for pid, id := range c.cache {
		snap.Global.AppIdentities[pid] = id
	}

	return nil
}

func (c *IdentityCollector) resolveIdentity(pid int) model.AppIdentity {
	pidDir := fmt.Sprintf("/proc/%d", pid)
	id := model.AppIdentity{PID: pid}

	// Read comm
	if data, err := os.ReadFile(filepath.Join(pidDir, "comm")); err == nil {
		id.Comm = strings.TrimSpace(string(data))
	} else {
		return id // process gone
	}

	// Read cmdline (null-separated)
	if data, err := os.ReadFile(filepath.Join(pidDir, "cmdline")); err == nil {
		cmd := string(data)
		cmd = strings.ReplaceAll(cmd, "\x00", " ")
		cmd = strings.TrimSpace(cmd)
		if len(cmd) > 256 {
			cmd = cmd[:256]
		}
		id.Cmdline = cmd
	}

	// Read exe symlink
	if target, err := os.Readlink(filepath.Join(pidDir, "exe")); err == nil {
		id.BinaryPath = strings.TrimSuffix(target, " (deleted)")
	}

	// Read cgroup
	if data, err := util.ReadFileString(filepath.Join(pidDir, "cgroup")); err == nil {
		for _, line := range strings.Split(data, "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
			if len(parts) == 3 && parts[0] == "0" {
				id.CgroupPath = parts[2]
				break
			}
		}
		if id.CgroupPath == "" {
			for _, line := range strings.Split(data, "\n") {
				parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
				if len(parts) == 3 {
					id.CgroupPath = parts[2]
					break
				}
			}
		}
	}

	// Read PPID from stat
	if data, err := util.ReadFileString(filepath.Join(pidDir, "stat")); err == nil {
		closeIdx := strings.LastIndex(data, ")")
		if closeIdx > 0 && closeIdx+2 < len(data) {
			fields := strings.Fields(data[closeIdx+2:])
			if len(fields) > 1 {
				id.ParentPID, _ = strconv.Atoi(fields[1])
			}
		}
	}

	// Read parent comm
	if id.ParentPID > 0 {
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", id.ParentPID)); err == nil {
			id.ParentComm = strings.TrimSpace(string(data))
		}
	}

	// Resolve service unit from cgroup
	id.ServiceUnit = resolveServiceUnit(id.CgroupPath)

	// Resolve container ID from cgroup
	id.ContainerID = resolveContainerID(id.CgroupPath)

	// Resolve application name using heuristic chain
	id.AppName, id.AppVersion = resolveAppName(id)

	// Build display name
	id.DisplayName = buildDisplayName(id)

	return id
}

// resolveServiceUnit extracts systemd unit name from cgroup path.
func resolveServiceUnit(cgPath string) string {
	if cgPath == "" {
		return ""
	}
	parts := strings.Split(strings.TrimRight(cgPath, "/"), "/")
	for _, p := range parts {
		if strings.HasSuffix(p, ".service") {
			return p
		}
	}
	return ""
}

// resolveContainerID extracts container ID from cgroup path.
func resolveContainerID(cgPath string) string {
	parts := strings.Split(strings.TrimRight(cgPath, "/"), "/")
	for _, p := range parts {
		if p == "docker" || strings.HasPrefix(p, "docker-") {
			leaf := parts[len(parts)-1]
			leaf = strings.TrimPrefix(leaf, "docker-")
			leaf = strings.TrimSuffix(leaf, ".scope")
			if len(leaf) > 12 {
				return leaf[:12]
			}
			return leaf
		}
		if strings.HasPrefix(p, "kubepods") {
			leaf := parts[len(parts)-1]
			for _, prefix := range []string{"cri-containerd-", "crio-", "docker-"} {
				leaf = strings.TrimPrefix(leaf, prefix)
			}
			leaf = strings.TrimSuffix(leaf, ".scope")
			if len(leaf) > 12 {
				return leaf[:12]
			}
			return leaf
		}
	}
	return ""
}

// resolveAppName runs the heuristic chain to identify the application.
func resolveAppName(id model.AppIdentity) (name, version string) {
	args := strings.Fields(id.Cmdline)

	// Priority 1: Java applications
	if id.Comm == "java" || strings.HasSuffix(id.BinaryPath, "/java") {
		return resolveJavaApp(args)
	}

	// Priority 2: Python applications
	if id.Comm == "python" || id.Comm == "python3" || id.Comm == "python2" {
		return resolvePythonApp(args)
	}

	// Priority 3: Node.js applications
	if id.Comm == "node" {
		return resolveNodeApp(args)
	}

	// Priority 4: .NET applications
	if id.Comm == "dotnet" {
		return resolveDotNetApp(args)
	}

	// Priority 5: Systemd unit name (strip .service)
	if id.ServiceUnit != "" {
		name = strings.TrimSuffix(id.ServiceUnit, ".service")
		return name, ""
	}

	// Priority 6: Container
	if id.ContainerID != "" {
		return "container:" + id.ContainerID, ""
	}

	// Priority 7: Binary path basename (if different from comm)
	if id.BinaryPath != "" {
		base := filepath.Base(id.BinaryPath)
		if base != id.Comm && base != "" && base != "." {
			return base, ""
		}
	}

	// Priority 8: Comm fallback
	return id.Comm, ""
}

// buildDisplayName creates the pre-formatted display string.
func buildDisplayName(id model.AppIdentity) string {
	name := id.AppName
	if name == "" {
		name = id.Comm
	}

	// Add version if available
	if id.AppVersion != "" {
		name += " " + id.AppVersion
	}

	// Build context parts
	var ctx []string
	if id.AppName != id.Comm && id.Comm != "" {
		ctx = append(ctx, id.Comm)
	}
	if id.ServiceUnit != "" && id.ServiceUnit != id.AppName+".service" {
		ctx = append(ctx, id.ServiceUnit)
	}
	if id.ContainerID != "" {
		ctx = append(ctx, "ctr:"+id.ContainerID)
	}

	if len(ctx) > 0 {
		return name + " [" + strings.Join(ctx, ", ") + "]"
	}
	return name
}
