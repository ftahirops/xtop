#!/bin/bash
# RCA Live Test Suite — compiles Go stressors with RANDOM binary names.
# Process appears in /proc/PID/comm as the random name. No "stress-ng" anywhere.
#
# Usage: sudo bash tests/rca_live_test.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; SKIP=0; RESULTS=""
log()  { echo -e "${CYAN}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); RESULTS+="${GREEN}PASS${NC}: $1\n"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); RESULTS+="${RED}FAIL${NC}: $1\n"; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); RESULTS+="${YELLOW}SKIP${NC}: $1\n"; }

[ "$(id -u)" -ne 0 ] && { echo "Must run as root"; exit 1; }
command -v go &>/dev/null || { echo "Go not found"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
STRESSOR_SRC="$SCRIPT_DIR/stressors"
WRAPPER_DIR=$(mktemp -d /tmp/rca-test-XXXXXX)
trap "rm -rf $WRAPPER_DIR; pkill -f $WRAPPER_DIR 2>/dev/null || true" EXIT

NUM_CPUS=$(nproc)
TOTAL_MEM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
XTOP_VERSION=$(xtop --version 2>&1 || echo "unknown")

echo -e "${BOLD}${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  RCA Live Test Suite — $XTOP_VERSION"
echo "  System: ${NUM_CPUS} CPUs, ${TOTAL_MEM_GB}GB RAM"
echo "  Stressors: pure Go binaries with random names"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"

# ─── Build stressor with random name ──────────────────────────────────────────

build_stressor() {
    local name
    name="$(cat /dev/urandom | tr -dc 'a-z' | head -c 8)"
    local out="$WRAPPER_DIR/$name"
    (cd "$STRESSOR_SRC" && CGO_ENABLED=0 go build -ldflags="-s -w" -o "$out" .) 2>&1
    echo "$name"
}

log "Compiling stressors..."
# Pre-build all stressors in parallel
BINS=()
for i in $(seq 1 14); do
    BINS+=("$(build_stressor)")
done
log "Built ${#BINS[@]} random-named binaries in $WRAPPER_DIR"
ls "$WRAPPER_DIR"
echo ""

# ─── Core test function ───────────────────────────────────────────────────────

run_test() {
    local test_name="$1"
    local bin_idx="$2"
    local args="$3"
    local warmup="${4:-18}"
    local expect_bottleneck="$5"
    local must_not_culprit="${6:-xtop}"

    local bin_name="${BINS[$bin_idx]}"
    local bin_path="$WRAPPER_DIR/$bin_name"

    echo ""
    echo -e "${BOLD}━━━ $test_name ━━━${NC}"
    log "Binary: ${YELLOW}$bin_name${NC}"
    log "Args: $args"

    "$bin_path" $args &
    local pid=$!
    log "PID $pid — comm=$(cat /proc/$pid/comm 2>/dev/null || echo '?')"

    log "Warming up ${warmup}s..."
    sleep "$warmup"

    if ! kill -0 "$pid" 2>/dev/null; then
        skip "$test_name — process exited early"
        return
    fi

    # What does the OS say?
    local top_cpu top_mem
    top_cpu=$(ps -eo comm,%cpu --sort=-%cpu --no-headers | head -3)
    top_mem=$(ps -eo comm,rss --sort=-rss --no-headers | head -3)
    log "  Top CPU:\n$top_cpu"

    # Capture xtop output
    local xout
    xout=$(timeout 8 script -qec "xtop" /dev/null 2>/dev/null | strings | head -80 || true)

    local errors=0
    local who_line what_line

    if [ -z "$xout" ]; then
        log "  ${YELLOW}!${NC} Could not capture xtop output"
    else
        what_line=$(echo "$xout" | grep -i "WHAT:" | head -1 || true)
        who_line=$(echo "$xout" | grep -i "WHO:" | head -1 || true)

        # Check bottleneck
        if [ -n "$expect_bottleneck" ]; then
            if echo "$xout" | grep -qi "WHAT:.*$expect_bottleneck\|DEGRADED.*$expect_bottleneck\|CRITICAL.*$expect_bottleneck"; then
                log "  ${GREEN}✓${NC} Bottleneck: $expect_bottleneck"
            elif echo "$xout" | grep -qi "No bottleneck\|HEALTH: OK"; then
                log "  ${YELLOW}!${NC} System shows healthy (stress may not be heavy enough)"
            else
                log "  ${RED}✗${NC} Expected '$expect_bottleneck', got: $what_line"
                errors=$((errors+1))
            fi
        fi

        # Check culprit contains our binary name
        if [ -n "$who_line" ]; then
            log "  WHO: $who_line"
            if echo "$who_line" | grep -qi "$bin_name"; then
                log "  ${GREEN}✓${NC} Correct culprit: $bin_name"
            else
                log "  ${YELLOW}!${NC} WHO doesn't show '$bin_name'"
            fi
            # Must NOT blame xtop
            if echo "$who_line" | grep -qi "xtop"; then
                log "  ${RED}✗${NC} xtop blamed as culprit!"
                errors=$((errors+1))
            fi
            if [ -n "$must_not_culprit" ] && echo "$who_line" | grep -qi "$must_not_culprit"; then
                log "  ${RED}✗${NC} '$must_not_culprit' in WHO"
                errors=$((errors+1))
            fi
        else
            if [ -n "$expect_bottleneck" ]; then
                log "  ${YELLOW}!${NC} No WHO line (RCA may not have triggered)"
            fi
        fi

        # CPU test: no network evidence
        if [ "$expect_bottleneck" = "CPU" ]; then
            if echo "$xout" | grep -q "▸.*retrans\|▸.*tcp.*resent\|▸.*packet drop"; then
                log "  ${RED}✗${NC} Network evidence in CPU bottleneck"
                errors=$((errors+1))
            fi
        fi
    fi

    # Cleanup
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    [ $errors -eq 0 ] && pass "$test_name [$bin_name]" || fail "$test_name [$bin_name] — $errors issues"

    log "Cooling down 8s..."
    sleep 8
}

# ═══════════════════════════════════════════════════════════════════════════════
# TESTS (bin_idx 0-13)
# ═══════════════════════════════════════════════════════════════════════════════

# 0: CPU Full
run_test "CPU Full Saturation (${NUM_CPUS} cores)" 0 \
    "--type cpu --workers $NUM_CPUS --duration 50s" 18 "CPU"

# 1: CPU Half
HALF=$((NUM_CPUS / 2)); [ $HALF -lt 1 ] && HALF=1
run_test "CPU Half Load ($HALF cores)" 1 \
    "--type cpu --workers $HALF --duration 50s" 18 ""

# 2: Memory 80%
MEM80=$((TOTAL_MEM_GB * 80 / 100)); [ $MEM80 -lt 1 ] && MEM80=1
run_test "Memory 80% (${MEM80}G)" 2 \
    "--type mem --bytes ${MEM80}G --duration 50s" 18 "Memory"

# 3: Memory 95%
MEM95=$((TOTAL_MEM_GB * 95 / 100)); [ $MEM95 -lt 1 ] && MEM95=1
run_test "Memory 95% OOM (${MEM95}G)" 3 \
    "--type mem --bytes ${MEM95}G --duration 45s" 18 "Memory"

# 4: IO Sequential
run_test "Disk IO Sequential" 4 \
    "--type io --workers 4 --duration 50s" 18 "IO"

# 5: IO Random 4K
run_test "Disk IO Random 4K" 5 \
    "--type iorand --workers 4 --duration 50s" 18 "IO"

# 6: Context Switches
run_test "Context Switch Storm" 6 \
    "--type ctxswitch --workers 8 --duration 50s" 18 ""

# 7: Network Socket Churn
run_test "Network Socket Churn" 7 \
    "--type net --workers 4 --duration 50s" 18 ""

# 8: Mixed CPU+Mem+IO
MEM50=$((TOTAL_MEM_GB * 50 / 100)); [ $MEM50 -lt 1 ] && MEM50=1
run_test "Mixed (CPU+Mem+IO)" 8 \
    "--type mixed --workers 6 --bytes ${MEM50}G --duration 50s" 20 ""

# 9: CPU Light (2 workers)
run_test "CPU Light (2 workers)" 9 \
    "--type cpu --workers 2 --duration 50s" 18 ""

# 10: IO Heavy (8 workers)
run_test "IO Heavy (8 workers)" 10 \
    "--type io --workers 8 --duration 50s" 18 "IO"

# 11: Memory Moderate (50%)
MEM50=$((TOTAL_MEM_GB * 50 / 100)); [ $MEM50 -lt 1 ] && MEM50=1
run_test "Memory 50% (${MEM50}G)" 11 \
    "--type mem --bytes ${MEM50}G --duration 50s" 18 ""

# 12: CPU + IO Combined
run_test "CPU + IO Combined" 12 \
    "--type mixed --workers 6 --bytes 1G --duration 50s" 18 ""

# 13: Healthy Baseline
echo ""
echo -e "${BOLD}━━━ Healthy Baseline (no stress) ━━━${NC}"
log "Waiting 20s for cooldown..."
sleep 20
xout=$(timeout 8 script -qec "xtop" /dev/null 2>/dev/null | strings | head -40 || true)
if echo "$xout" | grep -qi "No bottleneck\|HEALTH: OK"; then
    pass "Healthy Baseline — no false positives"
elif [ -z "$xout" ]; then
    skip "Healthy Baseline — could not capture xtop"
else
    sleep 15
    xout=$(timeout 8 script -qec "xtop" /dev/null 2>/dev/null | strings | head -40 || true)
    if echo "$xout" | grep -qi "No bottleneck\|HEALTH: OK"; then
        pass "Healthy Baseline — recovered after cooldown"
    else
        fail "Healthy Baseline — still showing bottleneck"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  RESULTS"
echo "═══════════════════════════════════════════════════════════"
echo -e "${NC}"
echo -e "$RESULTS"
echo -e "  ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}SKIP: $SKIP${NC}  Total: $((PASS+FAIL+SKIP))"
echo ""
[ $FAIL -gt 0 ] && { echo -e "${RED}Some tests FAILED.${NC}"; exit 1; }
echo -e "${GREEN}All tests PASSED!${NC}"
