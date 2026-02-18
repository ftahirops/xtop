#!/bin/bash
# Demo 6: Conntrack Exhaustion — reduce table size + flood connections
#
# What xtop shows:
#   HEALTH: DEGRADED/CRITICAL  PRIMARY: Network Overload
#   + Conntrack table pressure  XX% (XXXX/XXXX)
#   Network page:
#     CONNTRACK [||||||||||||||||    ] 85% (8500/10000)
#     -> Conntrack table > 80% — risk of dropped connections
#
# What htop shows: nothing
#
# Duration: 30 seconds
# Cleanup: automatic
# Requires: root (for sysctl)

set -e
echo "=== Demo 6: Conntrack Exhaustion ==="
echo "Run 'sudo xtop' in another terminal to watch."
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This demo requires root (for sysctl)."
    echo "  sudo bash $0"
    exit 1
fi

if [ ! -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
    echo "Conntrack not available (nf_conntrack module not loaded)."
    echo "Try: modprobe nf_conntrack"
    exit 1
fi

ORIG_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
echo "Original conntrack max: $ORIG_MAX"

# Reduce conntrack table to make exhaustion easy to demonstrate
NEW_MAX=1024
echo "Setting conntrack max to $NEW_MAX..."
echo "$NEW_MAX" > /proc/sys/net/netfilter/nf_conntrack_max

trap "echo '$ORIG_MAX' > /proc/sys/net/netfilter/nf_conntrack_max; kill \$(jobs -p) 2>/dev/null; echo 'Restored conntrack max to $ORIG_MAX. Cleaned up.'" EXIT

# Start a local server
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9998))
s.listen(2048)
while True:
    try:
        conn, _ = s.accept()
        conn.close()
    except: pass
" &
sleep 0.5

echo "Flooding connections to fill conntrack table..."
for i in $(seq 1 6); do
    (
        while true; do
            python3 -c "
import socket
for _ in range(50):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 9998))
        s.close()
    except: pass
" 2>/dev/null
        done
    ) &
done

echo "Conntrack flood running for 30 seconds..."
sleep 30

echo "Stopping..."
echo "$ORIG_MAX" > /proc/sys/net/netfilter/nf_conntrack_max
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
echo "Done. Check xtop for conntrack exhaustion detection."
