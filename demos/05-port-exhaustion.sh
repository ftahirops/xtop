#!/bin/bash
# Demo 5: Port Exhaustion — TIME_WAIT storm from rapid connections
#
# What xtop shows:
#   HEALTH: DEGRADED  PRIMARY: Network Overload
#   + TCP state anomaly    TW=XXXXX
#   Network page:
#     TIME_WAIT  XXXXX  (XX%) -> port exhaustion risk
#
# What htop shows: nothing
#
# Duration: 30 seconds
# Cleanup: automatic (TIME_WAIT sockets expire in ~60s)
# Requires: root (optional, for sysctl)

set -e
echo "=== Demo 5: Port Exhaustion (TIME_WAIT storm) ==="
echo "Run 'sudo xtop' in another terminal to watch."
echo ""

# Reduce TIME_WAIT timeout if root (makes demo more visible)
if [ "$(id -u)" -eq 0 ]; then
    echo "Reducing local port range for faster exhaustion..."
    ORIG_RANGE=$(cat /proc/sys/net/ipv4/ip_local_port_range)
    echo "32768 40000" > /proc/sys/net/ipv4/ip_local_port_range
    trap "echo '$ORIG_RANGE' > /proc/sys/net/ipv4/ip_local_port_range; kill \$(jobs -p) 2>/dev/null; echo 'Cleaned up.'" EXIT
else
    trap "kill \$(jobs -p) 2>/dev/null; echo 'Cleaned up.'" EXIT
fi

# Start a local server to connect to rapidly
python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9999))
s.listen(1024)
while True:
    try:
        conn, _ = s.accept()
        conn.close()
    except: pass
" &
SERVER_PID=$!
sleep 0.5

echo "Flooding connections to localhost:9999..."
for i in $(seq 1 8); do
    (
        while true; do
            # Rapid connect-close cycle creates TIME_WAIT
            python3 -c "
import socket
for _ in range(100):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 9999))
        s.close()
    except: pass
" 2>/dev/null
        done
    ) &
done

echo "Port exhaustion running for 30 seconds..."
sleep 30

echo "Stopping..."
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
echo "Done. Check xtop Network page for TIME_WAIT accumulation."
