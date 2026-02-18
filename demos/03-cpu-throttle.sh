#!/bin/bash
# Demo 3: CPU Throttling — cgroup-limited container burns CPU
#
# What xtop shows:
#   HEALTH: DEGRADED/CRITICAL  PRIMARY: CPU Contention [50%+]
#   + CPU PSI elevated         some=XX%
#   + Run queue saturated      X.X ratio
#   + Cgroup throttling        /demo-cpu-throttle 80%
#
# What htop shows: some busy CPUs, no throttle info
#
# Duration: 30 seconds
# Cleanup: automatic
# Requires: root (for cgroup creation)

set -e
echo "=== Demo 3: CPU Throttle (cgroup-limited workload) ==="
echo "Run 'sudo xtop' in another terminal to watch."
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This demo requires root (for cgroup creation)."
    echo "  sudo bash $0"
    exit 1
fi

CGPATH="/sys/fs/cgroup/demo-cpu-throttle"
trap "kill \$(jobs -p) 2>/dev/null; rmdir $CGPATH 2>/dev/null; echo 'Cleaned up.'" EXIT

echo "Creating cgroup with 50ms quota per 100ms period (50% of 1 CPU)..."
mkdir -p "$CGPATH"
echo "50000 100000" > "$CGPATH/cpu.max"

echo "Starting 4 CPU-burning threads in throttled cgroup..."
sleep 1

# Burn CPU in the throttled cgroup
for i in $(seq 1 4); do
    (
        echo $BASHPID > "$CGPATH/cgroup.procs"
        while true; do :; done
    ) &
done

# Also burn some CPU outside to create contention
for i in $(seq 1 4); do
    ( while true; do :; done ) &
done

echo "CPU contention running for 30 seconds..."
sleep 30

echo "Stopping..."
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
echo "Done. Check xtop for CPU throttling detection."
