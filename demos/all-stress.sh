#!/bin/bash
# all-stress.sh — Hit CPU, Memory, Disk IO, Network simultaneously using stress-ng
# Run with: sudo bash all-stress.sh
# Duration: 45 seconds, then auto-cleanup
set -e

DURATION=45
echo "=== ALL-SUBSYSTEM STRESS TEST ($DURATION seconds) ==="
echo "Open xtop in another terminal to watch!"
echo ""

PIDS=()
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true

    # Remove cgroup
    if [ -d /sys/fs/cgroup/demo-allstress ]; then
        rmdir /sys/fs/cgroup/demo-allstress 2>/dev/null || true
    fi

    # Remove tc qdisc
    tc qdisc del dev lo root 2>/dev/null || true

    # Remove temp files
    rm -f /tmp/stress_io_* /tmp/stress_srv_*.py

    echo "Done."
}
trap cleanup EXIT

# ─── 1. CPU STRESS (stress-ng + cgroup throttle) ────────────────
echo "[1/5] Starting CPU stress (stress-ng cpu + cgroup throttle)..."

# Create throttled cgroup (50% of 1 CPU)
mkdir -p /sys/fs/cgroup/demo-allstress
echo "50000 100000" > /sys/fs/cgroup/demo-allstress/cpu.max 2>/dev/null || true

# 2 CPU burners inside throttled cgroup
for i in 1 2; do
    (echo $BASHPID > /sys/fs/cgroup/demo-allstress/cgroup.procs 2>/dev/null || true
     while true; do :; done) &
    PIDS+=($!)
done

# stress-ng CPU workers (creates named "stress-ng-cpu" processes)
stress-ng --cpu 4 --cpu-method matrixprod --timeout ${DURATION}s --quiet &
PIDS+=($!)

# ─── 2. MEMORY STRESS (stress-ng vm) ───────────────────────────
echo "[2/5] Starting memory pressure (stress-ng vm workers)..."

TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
ALLOC_MB=$(( TOTAL_KB * 55 / 100 / 1024 ))
PER_PROC_MB=$(( ALLOC_MB / 3 ))

stress-ng --vm 3 --vm-bytes ${PER_PROC_MB}M --vm-keep --vm-method flip --timeout ${DURATION}s --quiet &
PIDS+=($!)

# ─── 3. DISK IO STRESS (stress-ng io + dd) ─────────────────────
echo "[3/5] Starting disk IO stress (stress-ng hdd + sync writers)..."

stress-ng --hdd 2 --hdd-bytes 128M --hdd-write-size 4K --timeout ${DURATION}s --quiet &
PIDS+=($!)

# Additional dd sync writers for heavy IO pressure
for i in 1 2; do
    dd if=/dev/zero of=/tmp/stress_io_$i bs=4K count=999999 conv=fdatasync 2>/dev/null &
    PIDS+=($!)
done

# ─── 4. NETWORK STRESS (tc netem + connections) ────────────────
echo "[4/5] Starting network stress (drops + retransmits + connections)..."

# Add packet loss and delay via tc
tc qdisc add dev lo root netem loss 8% corrupt 3% delay 30ms 2>/dev/null || true

# Start a local server for connection flooding
cat > /tmp/stress_srv_all.py << 'PYEOF'
import socket, threading, time
def handle(conn):
    try:
        time.sleep(0.5)
        conn.close()
    except:
        pass
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9877))
s.listen(512)
s.settimeout(1)
while True:
    try:
        conn, addr = s.accept()
        t = threading.Thread(target=handle, args=(conn,))
        t.daemon = True
        t.start()
    except socket.timeout:
        pass
    except:
        break
PYEOF
python3 /tmp/stress_srv_all.py &
PIDS+=($!)
sleep 0.5

# Connection flooders
for i in 1 2 3 4; do
    (while true; do
        for j in $(seq 1 50); do
            (echo "" > /dev/tcp/127.0.0.1/9877) 2>/dev/null || true
        done
        sleep 0.1
    done) &
    PIDS+=($!)
done

# stress-ng socket stressors
stress-ng --sock 2 --timeout ${DURATION}s --quiet &
PIDS+=($!)

# ─── 5. CONNTRACK PRESSURE ─────────────────────────────────────
echo "[5/5] Conntrack pressure (reducing max to 2048)..."
ORIG_CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
if [ "$ORIG_CT_MAX" -gt 0 ]; then
    echo 2048 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
    trap "echo $ORIG_CT_MAX > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null; cleanup" EXIT
fi

echo ""
echo "=== ALL STRESS RUNNING for $DURATION seconds ==="
echo "  CPU:     stress-ng --cpu 4 + 2 throttled burners"
echo "  Memory:  stress-ng --vm 3 (${ALLOC_MB}MB total)"
echo "  Disk IO: stress-ng --hdd 2 + 2 dd sync writers"
echo "  Network: tc loss 8% + stress-ng --sock 2 + connection flood"
echo "  Conntrack: max reduced to 2048"
echo ""
echo "Watch xtop now! Press Ctrl+C to stop early."
echo ""

sleep $DURATION
echo ""
echo "=== Stress test complete ==="
