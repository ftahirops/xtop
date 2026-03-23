#!/bin/bash
# nginx-stress.sh — Multi-port, multi-path HTTP load generator
# Hammers local nginx with high request rates across different endpoints
# Usage: ./nginx-stress.sh [duration_seconds] [concurrency]
#
# Creates multiple parallel workers hitting different ports and paths
# at different rates to simulate realistic mixed traffic patterns.

set -e

DURATION=${1:-30}
CONCURRENCY=${2:-50}
TOTAL_REQUESTS=100000  # per worker

# Colors
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
RST='\033[0m'

echo -e "${CYN}╭──────────────────────────────────────────────╮${RST}"
echo -e "${CYN}│  nginx stress test — multi-port multi-path   │${RST}"
echo -e "${CYN}│  Duration: ${DURATION}s  Concurrency: ${CONCURRENCY} per worker    │${RST}"
echo -e "${CYN}╰──────────────────────────────────────────────╯${RST}"
echo ""

# Create temp HTML pages for nginx to serve
WEBROOT="/var/www/html"
if [ ! -d "$WEBROOT" ]; then
    WEBROOT="/usr/share/nginx/html"
fi

# Create test pages if webroot exists and is writable
if [ -w "$WEBROOT" ] 2>/dev/null; then
    for i in 1 2 3 4 5; do
        cat > "$WEBROOT/stress-test-${i}.html" <<HTMLEOF
<!DOCTYPE html>
<html><head><title>Stress Test Page ${i}</title></head>
<body><h1>Load Test Page ${i}</h1>
<p>$(head -c 2048 /dev/urandom | base64 | head -c 1500)</p>
</body></html>
HTMLEOF
    done
    echo -e "${GRN}Created 5 test pages in $WEBROOT${RST}"
    PAGES_CREATED=true
else
    echo -e "${YLW}Cannot write to webroot, using existing endpoints${RST}"
    PAGES_CREATED=false
fi

# Detect what ports nginx listens on
NGINX_PORTS=$(ss -tlnp | grep nginx | awk '{print $4}' | grep -oP ':\K[0-9]+' | sort -un)
if [ -z "$NGINX_PORTS" ]; then
    NGINX_PORTS="80"
fi
echo -e "${CYN}Detected nginx ports: ${NGINX_PORTS}${RST}"

# Build target list: port + path combinations
declare -a TARGETS
for port in $NGINX_PORTS; do
    # Check if port is actually reachable
    if curl -s -o /dev/null -w "%{http_code}" --connect-timeout 1 "http://127.0.0.1:${port}/" 2>/dev/null | grep -qE '(200|301|302|403|404)'; then
        if [ "$PAGES_CREATED" = true ]; then
            for i in 1 2 3 4 5; do
                TARGETS+=("http://127.0.0.1:${port}/stress-test-${i}.html")
            done
        fi
        TARGETS+=("http://127.0.0.1:${port}/")
        TARGETS+=("http://127.0.0.1:${port}/nonexistent-$(date +%s)")  # 404s
    fi
done

# Also try HTTPS if port 443 is open
if curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 1 "https://127.0.0.1/" 2>/dev/null | grep -qE '(200|301|302|403|404)'; then
    TARGETS+=("https://127.0.0.1/")
    if [ "$PAGES_CREATED" = true ]; then
        for i in 1 2 3; do
            TARGETS+=("https://127.0.0.1/stress-test-${i}.html")
        done
    fi
fi

NUM_TARGETS=${#TARGETS[@]}
if [ "$NUM_TARGETS" -eq 0 ]; then
    echo -e "${RED}No reachable nginx targets found!${RST}"
    echo "Make sure nginx is running: systemctl status nginx"
    exit 1
fi

echo -e "${GRN}${NUM_TARGETS} target endpoints ready${RST}"
echo ""

# Launch workers
PIDS=()
RESULTS_DIR=$(mktemp -d)

echo -e "${YLW}Launching workers...${RST}"
for i in $(seq 0 $((NUM_TARGETS - 1))); do
    target="${TARGETS[$i]}"
    outfile="${RESULTS_DIR}/worker-${i}.txt"

    # Vary concurrency per worker (some heavy, some light)
    worker_conc=$((CONCURRENCY + (i * 7) % 30))
    worker_reqs=$((TOTAL_REQUESTS / NUM_TARGETS))
    if [ "$worker_reqs" -lt "$worker_conc" ]; then
        worker_reqs=$((worker_conc * 10))
    fi

    echo -e "  Worker ${i}: ${CYN}${target}${RST} (c=${worker_conc}, n=${worker_reqs})"

    # Use ab (Apache Bench) for each worker
    ab -n "$worker_reqs" -c "$worker_conc" -t "$DURATION" -s 2 -r "$target" > "$outfile" 2>&1 &
    PIDS+=($!)
done

echo ""
echo -e "${YLW}Running for ${DURATION}s across ${NUM_TARGETS} endpoints...${RST}"
echo -e "${CYN}Monitor in xtop: CPU, Network, and Overview pages${RST}"
echo ""

# Also run a burst of rapid curl requests for connection churn
(
    end=$((SECONDS + DURATION))
    while [ $SECONDS -lt $end ]; do
        for t in "${TARGETS[@]}"; do
            curl -s -o /dev/null "$t" &
        done
        # Don't overwhelm — small sleep between bursts
        sleep 0.05
    done
    wait
) &
CURL_PID=$!

# Progress bar
elapsed=0
while [ $elapsed -lt $DURATION ]; do
    # Check if any ab workers died early
    alive=0
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            alive=$((alive + 1))
        fi
    done

    pct=$((elapsed * 100 / DURATION))
    bar_len=$((pct / 2))
    bar=$(printf '%0.s█' $(seq 1 $bar_len 2>/dev/null) 2>/dev/null || echo "")
    spaces=$((50 - bar_len))
    space=$(printf '%0.s░' $(seq 1 $spaces 2>/dev/null) 2>/dev/null || echo "")
    printf "\r  ${CYN}[${bar}${space}]${RST} ${pct}%% (${elapsed}/${DURATION}s, ${alive} workers alive)  "

    sleep 1
    elapsed=$((elapsed + 1))
done
echo ""
echo ""

# Wait for all workers
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done
kill "$CURL_PID" 2>/dev/null || true
wait "$CURL_PID" 2>/dev/null || true

# Collect and display results
echo -e "${GRN}╭──────────────────────────────────────────────╮${RST}"
echo -e "${GRN}│              RESULTS SUMMARY                 │${RST}"
echo -e "${GRN}╰──────────────────────────────────────────────╯${RST}"
echo ""

total_requests=0
total_failed=0
for i in $(seq 0 $((NUM_TARGETS - 1))); do
    outfile="${RESULTS_DIR}/worker-${i}.txt"
    target="${TARGETS[$i]}"

    if [ -f "$outfile" ]; then
        completed=$(grep "Complete requests:" "$outfile" 2>/dev/null | awk '{print $3}' || echo "0")
        failed=$(grep "Failed requests:" "$outfile" 2>/dev/null | awk '{print $3}' || echo "0")
        rps=$(grep "Requests per second:" "$outfile" 2>/dev/null | awk '{print $4}' || echo "0")
        tpr=$(grep "Time per request:" "$outfile" 2>/dev/null | head -1 | awk '{print $4}' || echo "0")
        non2xx=$(grep "Non-2xx responses:" "$outfile" 2>/dev/null | awk '{print $3}' || echo "0")

        [ -z "$completed" ] && completed=0
        [ -z "$failed" ] && failed=0

        total_requests=$((total_requests + completed))
        total_failed=$((total_failed + failed))

        # Color code: green if OK, yellow if some failures, red if most failed
        if [ "$failed" -gt 0 ] && [ "$completed" -gt 0 ]; then
            fail_pct=$((failed * 100 / completed))
            if [ "$fail_pct" -gt 50 ]; then
                color="$RED"
            else
                color="$YLW"
            fi
        else
            color="$GRN"
        fi

        printf "  ${color}%-50s${RST}  %6s req  %6s rps  %4s fail" \
            "$(echo "$target" | tail -c 50)" \
            "$completed" "$rps" "$failed"
        [ -n "$non2xx" ] && [ "$non2xx" != "0" ] && printf "  ${YLW}(${non2xx} non-2xx)${RST}"
        echo ""
    fi
done

echo ""
echo -e "  ${CYN}Total requests: ${total_requests}${RST}"
echo -e "  ${CYN}Total failed:   ${total_failed}${RST}"
echo ""

# Cleanup
rm -rf "$RESULTS_DIR"
if [ "$PAGES_CREATED" = true ]; then
    rm -f "$WEBROOT"/stress-test-*.html 2>/dev/null
fi

echo -e "${GRN}Done! Check xtop for the impact.${RST}"
