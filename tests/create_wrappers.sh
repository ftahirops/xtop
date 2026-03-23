#!/bin/bash
# Creates randomly-named wrapper binaries that invoke stress-ng.
# This ensures RCA tests can't cheat by matching "stress-ng" in the process name.

set -euo pipefail

WRAPPER_DIR="/tmp/rca-test-wrappers"
rm -rf "$WRAPPER_DIR"
mkdir -p "$WRAPPER_DIR"

# Generate random 6-char names
rand_name() { cat /dev/urandom | tr -dc 'a-z' | head -c 6; }

NAMES=()
TYPES=("cpu" "mem" "diskseq" "disk4k" "diskfsync" "ctxswitch" "pgfault" "mixed" "sock" "cache" "futex" "memoom" "cpuhalf")

for type in "${TYPES[@]}"; do
    name="$(rand_name)_${type}"
    wrapper="$WRAPPER_DIR/$name"
    cat > "$wrapper" <<'INNER'
#!/bin/bash
exec stress-ng "$@"
INNER
    chmod +x "$wrapper"
    NAMES+=("$name")
    echo "$type=$name"
done

echo ""
echo "WRAPPER_DIR=$WRAPPER_DIR"
echo "Wrappers created: ${#NAMES[@]}"
ls -la "$WRAPPER_DIR"/
