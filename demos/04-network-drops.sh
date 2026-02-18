#!/bin/bash
# Demo 4: Network Drops — simulate packet loss with tc netem
#
# What xtop shows:
#   HEALTH: DEGRADED  PRIMARY: Network Overload [40%+]
#   + Packet drops          XX/s
#   + TCP retransmits       XX/s
#
# What htop shows: nothing
#
# Duration: 30 seconds
# Cleanup: automatic
# Requires: root, tc (iproute2), and a network interface

set -e
echo "=== Demo 4: Network Drops (tc netem + traffic) ==="
echo "Run 'sudo xtop' in another terminal to watch."
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This demo requires root (for tc)."
    echo "  sudo bash $0"
    exit 1
fi

# Find a non-loopback interface
IFACE=$(ip -o link show | grep -v lo: | head -1 | awk -F: '{print $2}' | tr -d ' ')
if [ -z "$IFACE" ]; then
    echo "No network interface found."
    exit 1
fi

echo "Using interface: $IFACE"
trap "tc qdisc del dev $IFACE root 2>/dev/null; kill \$(jobs -p) 2>/dev/null; echo 'Cleaned up.'" EXIT

echo "Adding 10% packet loss + 5% corruption on $IFACE..."
tc qdisc add dev "$IFACE" root netem loss 10% corrupt 5% delay 50ms 2>/dev/null || {
    echo "tc netem failed. Try: apt install iproute2"
    exit 1
}

echo "Generating network traffic to trigger retransmits..."
# Generate traffic that will hit the loss
for i in $(seq 1 3); do
    (
        while true; do
            curl -s -o /dev/null --connect-timeout 2 http://1.1.1.1/ 2>/dev/null || true
            sleep 0.1
        done
    ) &
done

# Also try TCP connections that will see retransmits
for i in $(seq 1 3); do
    (
        while true; do
            timeout 2 bash -c "echo > /dev/tcp/1.1.1.1/80" 2>/dev/null || true
            sleep 0.2
        done
    ) &
done

echo "Network drops running for 30 seconds..."
sleep 30

echo "Stopping..."
tc qdisc del dev "$IFACE" root 2>/dev/null
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
echo "Done. Check xtop for network overload detection."
