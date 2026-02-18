#!/bin/bash
# Demo 2: Memory Pressure — allocate until reclaim kicks in
#
# What xtop shows:
#   HEALTH: CRITICAL  PRIMARY: Memory Pressure [70%+]
#   + MEM PSI elevated      some=XX% full=XX%
#   + MemAvailable low      X% (low free)
#   + Swap IO active        X MB/s
#   + Direct reclaim active X pages/s
#
# What htop shows: high memory bar, maybe some swap
#
# Duration: 30 seconds
# Cleanup: automatic (processes die = memory freed)

set -e
echo "=== Demo 2: Memory Pressure (allocate + reclaim) ==="
echo "Run 'sudo xtop' in another terminal to watch."
echo ""

# Calculate ~70% of total RAM
TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TARGET_MB=$(( TOTAL_KB / 1024 * 70 / 100 ))
PER_PROC_MB=$(( TARGET_MB / 4 ))

echo "Total RAM: $(( TOTAL_KB / 1024 ))MB, will allocate ~${TARGET_MB}MB"
echo "Starting in 3s..."
sleep 3

# stress-ng is best for this, but fallback to python if not available
if command -v stress-ng &>/dev/null; then
    echo "Using stress-ng..."
    stress-ng --vm 4 --vm-bytes "${PER_PROC_MB}M" --vm-keep --timeout 30s &
elif command -v python3 &>/dev/null; then
    echo "Using python3 memory allocator..."
    for i in $(seq 1 4); do
        python3 -c "
import time
data = bytearray(${PER_PROC_MB} * 1024 * 1024)
# Touch pages to force allocation
for i in range(0, len(data), 4096):
    data[i] = 1
time.sleep(30)
" &
    done
else
    echo "Neither stress-ng nor python3 found. Install stress-ng:"
    echo "  apt install stress-ng"
    exit 1
fi

echo "Memory pressure running for 30 seconds..."
sleep 30

echo "Stopping..."
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
echo "Done. Check xtop for memory pressure detection."
