package collector

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ftahirops/xtop/model"
)

// SecurityCollector gathers security-related metrics.
type SecurityCollector struct {
	// Auth log state
	authOffset    int64
	authInode     uint64
	lastAuthTime  time.Time
	failedAuthIPs map[string]int
	lastDecay     time.Time // #2: periodic decay for failedAuthIPs

	// Port baseline
	portBaseline  map[int]bool
	portInit      bool
	portInitTime  time.Time // #12: grace period for port baseline promotion

	// SUID baseline
	suidBaseline  map[string]time.Time
	suidInit      bool
	suidInitTime  time.Time // #12: grace period for SUID baseline promotion
	lastSUIDScan  time.Time
}

func (s *SecurityCollector) Name() string { return "security" }

var failedAuthRE = regexp.MustCompile(`Failed password.*from\s+(\S+)`)
var authFailureRE = regexp.MustCompile(`authentication failure.*rhost=(\S+)`)

// reverseShellWhitelist: legitimate processes that commonly have stdin+stdout as sockets (#13)
var reverseShellWhitelist = map[string]bool{
	"sshd": true, "ssh": true, "postgres": true, "mysqld": true, "mariadbd": true,
	"mongod": true, "redis-server": true, "node": true, "java": true,
	"nginx": true, "apache2": true, "httpd": true, "haproxy": true,
	"containerd": true, "dockerd": true, "kubelet": true, "kube-proxy": true,
	"systemd": true, "systemd-resolved": true, "systemd-networkd": true,
	"dbus-daemon": true, "polkitd": true, "rsyslogd": true,
	"master": true, "postfix": true, "dovecot": true, "exim4": true,
	"named": true, "unbound": true, "dnsmasq": true, "chronyd": true, "ntpd": true,
}

func (s *SecurityCollector) Collect(snap *model.Snapshot) error {
	if s.failedAuthIPs == nil {
		s.failedAuthIPs = make(map[string]int)
	}

	// #2: Decay failedAuthIPs every 5 minutes to prevent unbounded growth
	now := time.Now()
	if !s.lastDecay.IsZero() && now.Sub(s.lastDecay) >= 5*time.Minute {
		for ip, count := range s.failedAuthIPs {
			newCount := count / 2
			if newCount <= 0 {
				delete(s.failedAuthIPs, ip)
			} else {
				s.failedAuthIPs[ip] = newCount
			}
		}
		// Also cap map size at 1000 entries
		if len(s.failedAuthIPs) > 1000 {
			type ipCount struct {
				ip    string
				count int
			}
			var ips []ipCount
			for ip, c := range s.failedAuthIPs {
				ips = append(ips, ipCount{ip, c})
			}
			sort.Slice(ips, func(i, j int) bool { return ips[i].count > ips[j].count })
			s.failedAuthIPs = make(map[string]int, 1000)
			for i, ic := range ips {
				if i >= 1000 {
					break
				}
				s.failedAuthIPs[ic.ip] = ic.count
			}
		}
		s.lastDecay = now
	}
	if s.lastDecay.IsZero() {
		s.lastDecay = now
	}

	sec := &snap.Global.Security
	sec.Score = "OK"

	s.collectAuthLog(sec)
	s.collectNewPorts(snap, sec)
	s.collectSUID(sec)
	s.collectReverseShells(snap, sec)
	s.collectSessions(snap)

	// Compute overall score
	if sec.BruteForce || len(sec.ReverseShells) > 0 || len(sec.SUIDAnomalies) > 0 {
		sec.Score = "CRIT"
	} else if sec.FailedAuthRate > 1 || len(sec.NewPorts) > 0 {
		sec.Score = "WARN"
	}

	return nil
}

func (s *SecurityCollector) collectAuthLog(sec *model.SecurityMetrics) {
	now := time.Now()
	deltaS := now.Sub(s.lastAuthTime).Seconds()
	if deltaS < 0.5 {
		deltaS = 1
	}
	s.lastAuthTime = now

	lines := s.readAuthLogIncremental()
	if lines == nil {
		lines = s.readJournalSSH()
	}

	failCount := 0
	for _, line := range lines {
		if m := failedAuthRE.FindStringSubmatch(line); m != nil {
			failCount++
			s.failedAuthIPs[m[1]]++
		} else if m := authFailureRE.FindStringSubmatch(line); m != nil {
			failCount++
			s.failedAuthIPs[m[1]]++
		}
	}

	sec.FailedAuthTotal = 0
	for _, c := range s.failedAuthIPs {
		sec.FailedAuthTotal += c
	}
	sec.FailedAuthRate = float64(failCount) / deltaS

	// Brute force detection: >10 failures/minute
	if sec.FailedAuthRate > 10.0/60.0 {
		sec.BruteForce = true
	}

	// Top failed IPs
	type ipCount struct {
		ip    string
		count int
	}
	var ips []ipCount
	for ip, c := range s.failedAuthIPs {
		ips = append(ips, ipCount{ip, c})
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].count > ips[j].count })
	if len(ips) > 10 {
		ips = ips[:10]
	}
	sec.FailedAuthIPs = nil
	for _, ic := range ips {
		sec.FailedAuthIPs = append(sec.FailedAuthIPs, model.FailedAuthSource{
			IP:    model.MaskIP(ic.ip),
			Count: ic.count,
		})
	}
}

func (s *SecurityCollector) readAuthLogIncremental() []string {
	const authLog = "/var/log/auth.log"
	fi, err := os.Stat(authLog)
	if err != nil {
		return nil
	}

	// #9: Fix inode detection — use syscall.Stat_t directly
	currentInode := uint64(0)
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		currentInode = stat.Ino
	}

	if currentInode != 0 && currentInode != s.authInode {
		s.authOffset = 0
		s.authInode = currentInode
	}

	f, err := os.Open(authLog)
	if err != nil {
		return nil
	}
	defer f.Close()

	size := fi.Size()
	if s.authOffset > size {
		s.authOffset = 0
	}
	if s.authOffset == 0 && size > 32*1024 {
		s.authOffset = size - 32*1024
	}

	if _, err := f.Seek(s.authOffset, 0); err != nil {
		return nil
	}

	var lines []string
	scanner := bufio.NewScanner(f)

	// #4: If we seeked to a non-zero offset, discard the first partial line
	if s.authOffset > 0 {
		scanner.Scan() // discard partial line
	}

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	newOffset, _ := f.Seek(0, 1)
	s.authOffset = newOffset

	return lines
}

func (s *SecurityCollector) readJournalSSH() []string {
	out, err := exec.Command("journalctl", "-u", "ssh", "-u", "sshd",
		"--since", "5s ago", "--no-pager", "-o", "cat").Output()
	if err != nil {
		return nil
	}
	if len(out) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func (s *SecurityCollector) collectNewPorts(snap *model.Snapshot, sec *model.SecurityMetrics) {
	currentPorts := make(map[int]bool)
	listenPorts := getListenPorts()
	for _, p := range listenPorts {
		currentPorts[p.port] = true
	}

	if !s.portInit {
		s.portBaseline = currentPorts
		s.portInit = true
		s.portInitTime = time.Now()
		return
	}

	// #12: Promote new ports into baseline after 5-minute grace period
	if time.Since(s.portInitTime) > 5*time.Minute {
		for port := range currentPorts {
			s.portBaseline[port] = true
		}
		s.portInitTime = time.Now()
	}

	sec.NewPorts = nil
	for _, p := range listenPorts {
		if !s.portBaseline[p.port] {
			sec.NewPorts = append(sec.NewPorts, model.NewListeningPort{
				Port:  p.port,
				PID:   p.pid,
				Comm:  p.comm,
				Since: time.Now(),
			})
		}
	}
}

type listenPortInfo struct {
	port int
	pid  int
	comm string
}

func getListenPorts() []listenPortInfo {
	var ports []listenPortInfo
	seen := make(map[int]bool)

	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ports
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// State 0A = LISTEN
		if fields[3] != "0A" {
			continue
		}
		// Parse local address
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 {
			continue
		}
		port := 0
		fmt.Sscanf(parts[1], "%X", &port)
		if port > 0 && !seen[port] {
			seen[port] = true
			ports = append(ports, listenPortInfo{port: port})
		}
	}

	// Also check tcp6
	f6, err := os.Open("/proc/net/tcp6")
	if err != nil {
		return ports
	}
	defer f6.Close()

	scanner6 := bufio.NewScanner(f6)
	scanner6.Scan() // skip header
	for scanner6.Scan() {
		fields := strings.Fields(scanner6.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) < 2 {
			continue
		}
		port := 0
		fmt.Sscanf(parts[len(parts)-1], "%X", &port)
		if port > 0 && !seen[port] {
			seen[port] = true
			ports = append(ports, listenPortInfo{port: port})
		}
	}

	return ports
}

func (s *SecurityCollector) collectSUID(sec *model.SecurityMetrics) {
	now := time.Now()
	if s.suidInit && now.Sub(s.lastSUIDScan) < 60*time.Second {
		return
	}
	s.lastSUIDScan = now

	currentSUID := make(map[string]time.Time)
	suidDirs := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin"}

	for _, dir := range suidDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSetuid != 0 {
				path := dir + "/" + e.Name()
				currentSUID[path] = info.ModTime()
			}
		}
	}

	if !s.suidInit {
		s.suidBaseline = currentSUID
		s.suidInit = true
		s.suidInitTime = now
		return
	}

	// #12: Promote new SUID binaries into baseline after 5-minute grace period
	if now.Sub(s.suidInitTime) > 5*time.Minute {
		for path, modTime := range currentSUID {
			s.suidBaseline[path] = modTime
		}
		s.suidInitTime = now
	}

	sec.SUIDAnomalies = nil
	for path, modTime := range currentSUID {
		if _, inBaseline := s.suidBaseline[path]; !inBaseline {
			sec.SUIDAnomalies = append(sec.SUIDAnomalies, model.SUIDBinary{
				Path:    path,
				Owner:   "root",
				ModTime: modTime,
			})
		}
	}
}

func (s *SecurityCollector) collectReverseShells(snap *model.Snapshot, sec *model.SecurityMetrics) {
	sec.ReverseShells = nil

	procs := snap.Processes
	if len(procs) > 50 {
		procs = procs[:50]
	}

	for _, p := range procs {
		if p.PID < 100 {
			continue
		}
		// #13: Skip whitelisted processes to reduce false positives
		if reverseShellWhitelist[p.Comm] {
			continue
		}
		fd0 := readFDLink(p.PID, 0)
		fd1 := readFDLink(p.PID, 1)

		if strings.HasPrefix(fd0, "socket:[") && strings.HasPrefix(fd1, "socket:[") {
			sec.ReverseShells = append(sec.ReverseShells, model.ReverseShellProc{
				PID:  p.PID,
				Comm: p.Comm,
				FD0:  fd0,
				FD1:  fd1,
			})
		}
	}
}

func readFDLink(pid, fd int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return ""
	}
	return target
}

func (s *SecurityCollector) collectSessions(snap *model.Snapshot) {
	snap.Global.Sessions = nil

	out, err := exec.Command("w").Output()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return
	}

	// Parse column positions from header
	header := lines[1]
	colUser := strings.Index(header, "USER")
	colTTY := strings.Index(header, "TTY")
	colFrom := strings.Index(header, "FROM")
	colLogin := strings.Index(header, "LOGIN@")
	colIdle := strings.Index(header, "IDLE")
	colJCPU := strings.Index(header, "JCPU")
	colWhat := strings.Index(header, "WHAT")

	// #17: Validate ALL column indices before using them
	if colUser < 0 || colTTY < 0 || colFrom < 0 || colLogin < 0 ||
		colIdle < 0 || colJCPU < 0 || colWhat < 0 {
		return
	}

	for _, line := range lines[2:] {
		if line == "" || len(line) < colWhat {
			continue
		}
		user := strings.TrimSpace(sliceSafe(line, colUser, colTTY))
		tty := strings.TrimSpace(sliceSafe(line, colTTY, colFrom))
		from := strings.TrimSpace(sliceSafe(line, colFrom, colLogin))
		loginAt := strings.TrimSpace(sliceSafe(line, colLogin, colIdle-1))
		idle := strings.TrimSpace(sliceSafe(line, colIdle-1, colJCPU))
		cmd := strings.TrimSpace(sliceSafe(line, colWhat, len(line)))

		snap.Global.Sessions = append(snap.Global.Sessions, model.ActiveSession{
			User:    user,
			TTY:     tty,
			From:    model.MaskIP(from),
			LoginAt: loginAt,
			Idle:    idle,
			Command: cmd,
		})
	}
}

func sliceSafe(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end < 0 {
		end = 0
	}
	if start >= len(s) {
		return ""
	}
	if end > len(s) {
		end = len(s)
	}
	if end < start {
		return ""
	}
	return s[start:end]
}
