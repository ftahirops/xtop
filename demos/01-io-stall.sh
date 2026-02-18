#!/bin/bash
# Demo 1: IO Stall — heavy synchronous writes cause D-state + PSI IO pressure
#
# What xtop shows:
#   HEALTH: CRITICAL  PRIMARY: IO Starvation [85%+]
#   + IO PSI elevated     some=XX% full=XX%
#   + D-state tasks       N tasks
#   + Disk latency/util   sdX await=XXms util=98%
#
# What htop shows: nothing useful (maybe high iowait %)
#
# Duration: 30 seconds
# Cleanup: automatic

set -e
echo "=== Demo 1: IO Stall (sync writes + fsync) ==="
echo "Run 'sudo xtop' in another terminal to watch."
echo ""
echo "Starting in 3s..."
sleep 3

# Create temp dir
TMPDIR=$(mktemp -d /tmp/xtop-demo-XXXXX)
trap "rm -rf $TMPDIR; echo 'Cleaned up.'" EXIT

echo "Generating heavy synchronous IO..."
# Multiple sync writers to saturate the IO subsystem
for i in $(seq 1 4); do
    (
        while true; do
            dd if=/dev/zero of="$TMPDIR/file-$i" bs=4K count=1024 conv=fdatasync 2>/dev/null
        done
    ) &
done

# Also do random reads to increase await
(
    while true; do
        dd if=/dev/urandom of="$TMPDIR/random" bs=64K count=256 oflag=sync 2>/dev/null
    done
) &

echo "IO load running for 30 seconds (PID: $$)..."
sleep 30

echo "Stopping..."
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
echo "Done. Check xtop for IO starvation detection."
