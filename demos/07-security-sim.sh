#!/usr/bin/env bash
# 07-security-sim.sh — simulate attack patterns to verify execsnoop + ptrace BPF probes
# Run this while watching:  sudo xtop  → press L (Security page)
#
# Usage:  bash demos/07-security-sim.sh [scenario]
# Scenarios: all, recon, privesc, c2, miner, inject, lateral

set -e

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
DIM='\033[2m'
RST='\033[0m'

banner() { echo -e "\n${RED}[ATTACK]${RST} ${YEL}$1${RST}"; }
info()   { echo -e "  ${DIM}$1${RST}"; }
pause()  { sleep "${1:-1}"; }

# ---------- Scenario 1: Reconnaissance ----------
scenario_recon() {
    banner "RECON — attacker enumerating the system"

    info "whoami / id / hostname"
    whoami >/dev/null 2>&1
    id >/dev/null 2>&1
    hostname >/dev/null 2>&1
    pause 0.3

    info "uname -a (kernel fingerprinting)"
    uname -a >/dev/null 2>&1
    pause 0.3

    info "cat /etc/passwd (user enumeration)"
    cat /etc/passwd >/dev/null 2>&1
    pause 0.3

    info "ps aux (process listing)"
    ps aux >/dev/null 2>&1
    pause 0.3

    info "ss -tlnp (open ports)"
    ss -tlnp >/dev/null 2>&1
    pause 0.3

    info "find SUID binaries"
    find /usr/bin -perm -4000 -type f 2>/dev/null | head -5 >/dev/null
    pause 0.3

    info "ip addr / ip route (network recon)"
    ip addr >/dev/null 2>&1
    ip route >/dev/null 2>&1
    pause 0.3

    info "cat /etc/shadow attempt (will fail)"
    cat /etc/shadow >/dev/null 2>&1 || true
    pause 0.3

    echo -e "  ${GRN}[OK]${RST} Recon done — check execsnoop for whoami/id/ps/ss/find/ip"
}

# ---------- Scenario 2: Privilege Escalation ----------
scenario_privesc() {
    banner "PRIVESC — simulating privilege escalation attempts"

    info "sudo -l (checking sudo privileges)"
    sudo -l >/dev/null 2>&1 || true
    pause 0.3

    info "Spawning a root shell via sudo sh -c 'id'"
    sudo sh -c 'id >/dev/null 2>&1'
    pause 0.3

    info "Checking capabilities: getcap"
    getcap /usr/bin/* 2>/dev/null | head -3 >/dev/null || true
    pause 0.3

    info "Trying pkexec (polkit)"
    pkexec --help >/dev/null 2>&1 || true
    pause 0.3

    echo -e "  ${GRN}[OK]${RST} Privesc done — check execsnoop for UID=0 root execs (yellow)"
}

# ---------- Scenario 3: C2 Beacon Simulation ----------
scenario_c2() {
    banner "C2 BEACON — simulating command-and-control callbacks"

    info "curl to external IP (simulated C2 check-in)"
    curl -s --max-time 2 http://1.1.1.1 >/dev/null 2>&1 || true
    pause 0.5

    info "wget download attempt"
    wget -q --timeout=2 -O /dev/null http://1.1.1.1 2>/dev/null || true
    pause 0.5

    info "nslookup suspicious domain"
    nslookup evil.example.com >/dev/null 2>&1 || true
    pause 0.3

    info "base64 decode pipe to sh (classic dropper pattern)"
    echo "ZWNobyBoZWxsbw==" | base64 -d 2>/dev/null | sh >/dev/null 2>&1 || true
    pause 0.3

    info "Python reverse shell one-liner (dry run, no actual connection)"
    python3 -c "import sys; sys.exit(0)" 2>/dev/null || true
    pause 0.3

    echo -e "  ${GRN}[OK]${RST} C2 done — check execsnoop for curl/wget/nslookup/python3/base64/sh"
}

# ---------- Scenario 4: Cryptominer Simulation ----------
scenario_miner() {
    banner "CRYPTOMINER — simulating mining activity"

    info "Spawning CPU-intensive processes (short-lived)"
    for i in $(seq 1 5); do
        dd if=/dev/urandom bs=1024 count=100 2>/dev/null | md5sum >/dev/null 2>&1 &
    done
    wait
    pause 0.3

    info "xmrig-like process name (harmless sleep)"
    cp /usr/bin/sleep /tmp/.xmrig-notavirus 2>/dev/null || true
    /tmp/.xmrig-notavirus 0.1 2>/dev/null || true
    rm -f /tmp/.xmrig-notavirus
    pause 0.3

    info "Hidden dotfile execution"
    cp /usr/bin/true /tmp/.hidden_task 2>/dev/null || true
    /tmp/.hidden_task 2>/dev/null || true
    rm -f /tmp/.hidden_task
    pause 0.3

    echo -e "  ${GRN}[OK]${RST} Miner done — check execsnoop for dd/md5sum/.xmrig/.hidden_task"
}

# ---------- Scenario 5: Process Injection (ptrace) ----------
scenario_inject() {
    banner "PTRACE INJECTION — simulating debugger/injector activity"

    # Start a dummy target process
    sleep 300 &
    TARGET_PID=$!
    info "Target process: sleep (PID $TARGET_PID)"
    pause 0.5

    info "strace attach (PTRACE_ATTACH + PTRACE_SEIZE)"
    timeout 2 strace -p "$TARGET_PID" -e trace=none -o /dev/null 2>/dev/null &
    STRACE_PID=$!
    pause 2
    kill "$STRACE_PID" 2>/dev/null || true
    wait "$STRACE_PID" 2>/dev/null || true
    pause 0.5

    info "gdb attach (PTRACE_ATTACH)"
    if command -v gdb >/dev/null 2>&1; then
        timeout 2 gdb -batch -ex "attach $TARGET_PID" -ex "detach" -ex "quit" 2>/dev/null || true
        pause 0.5
    else
        info "  (gdb not installed, skipping)"
    fi

    info "ltrace attach"
    if command -v ltrace >/dev/null 2>&1; then
        timeout 2 ltrace -p "$TARGET_PID" -e none -o /dev/null 2>/dev/null &
        LT_PID=$!
        pause 2
        kill "$LT_PID" 2>/dev/null || true
        wait "$LT_PID" 2>/dev/null || true
    else
        info "  (ltrace not installed, skipping)"
    fi

    # Cleanup target
    kill "$TARGET_PID" 2>/dev/null || true
    wait "$TARGET_PID" 2>/dev/null || true

    echo -e "  ${GRN}[OK]${RST} Inject done — check PTRACE DETECTION for strace/gdb/ltrace entries"
}

# ---------- Scenario 6: Lateral Movement ----------
scenario_lateral() {
    banner "LATERAL MOVEMENT — simulating post-exploitation"

    info "ssh-keygen (creating keys for persistence)"
    ssh-keygen -t ed25519 -f /tmp/test_lateral_key -N "" -q 2>/dev/null || true
    rm -f /tmp/test_lateral_key /tmp/test_lateral_key.pub
    pause 0.3

    info "scp / ssh attempt (will fail, but exec is logged)"
    ssh -o BatchMode=yes -o ConnectTimeout=1 127.0.0.1 true 2>/dev/null || true
    pause 0.3

    info "tar + pipe (data exfiltration pattern)"
    tar czf /dev/null /etc/hostname 2>/dev/null || true
    pause 0.3

    info "nc (netcat) listener attempt"
    if command -v nc >/dev/null 2>&1; then
        timeout 1 nc -l -p 0 2>/dev/null || true
    elif command -v ncat >/dev/null 2>&1; then
        timeout 1 ncat -l 2>/dev/null || true
    else
        info "  (nc not installed, skipping)"
    fi
    pause 0.3

    echo -e "  ${GRN}[OK]${RST} Lateral done — check execsnoop for ssh-keygen/ssh/tar/nc"
}

# ---------- Main ----------
run_all() {
    scenario_recon
    scenario_privesc
    scenario_c2
    scenario_miner
    scenario_inject
    scenario_lateral
}

SCENARIO="${1:-all}"

echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${RED}  SECURITY VERIFICATION — Attack Scenario Simulator${RST}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${DIM}  Make sure xtop is running:  sudo xtop → press L${RST}"
echo ""

case "$SCENARIO" in
    all)     run_all ;;
    recon)   scenario_recon ;;
    privesc) scenario_privesc ;;
    c2)      scenario_c2 ;;
    miner)   scenario_miner ;;
    inject)  scenario_inject ;;
    lateral) scenario_lateral ;;
    *)
        echo "Unknown scenario: $SCENARIO"
        echo "Usage: $0 [all|recon|privesc|c2|miner|inject|lateral]"
        exit 1
        ;;
esac

echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${GRN}  DONE${RST} — Switch to xtop Security page (L) to verify"
echo -e ""
echo -e "  ${YEL}PROCESS EXECUTIONS (BPF)${RST} should show:"
echo -e "    - All executed binaries with PID, PPID, UID, filename"
echo -e "    - Root execs (UID=0) highlighted in yellow"
echo -e ""
echo -e "  ${YEL}PTRACE DETECTION (BPF)${RST} should show:"
echo -e "    - strace → PTRACE_ATTACH / PTRACE_SEIZE"
echo -e "    - gdb    → PTRACE_ATTACH"
echo -e "    - Each tracer-target pair tracked separately"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
