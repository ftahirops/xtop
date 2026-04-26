#!/usr/bin/env bash
# Build an RPM for the latest xtop deb. Relies on `alien` for reproducible
# conversion rather than maintaining a parallel spec file — the deb/control
# is the single source of truth for versioning and file layout.
#
# Usage:
#   packaging/rpm-build.sh [VERSION]        # default: reads from cmd/root.go
#
# Requirements: dpkg-deb, alien (apt install dpkg alien)
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(grep -oP 'Version\s*=\s*"\K[0-9.]+' cmd/root.go | head -1)}"
DEB="packaging/xtop_${VERSION}-1_amd64.deb"
RPM="packaging/xtop-${VERSION}-1.x86_64.rpm"

if [[ ! -f "$DEB" ]]; then
  echo "Deb not found: $DEB" >&2
  echo "Build it first: dpkg-deb --build packaging/xtop_${VERSION}-1_amd64" >&2
  exit 1
fi

if ! command -v alien >/dev/null; then
  echo "alien not installed (apt install alien)" >&2
  exit 1
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
# alien writes to its CWD; resolve the deb's absolute path first so the cd
# into workdir doesn't break the source lookup.
abs_deb=$(realpath "$DEB")
(cd "$workdir" && alien --to-rpm --scripts --keep-version "$abs_deb" >/dev/null)
mv "$workdir/xtop-${VERSION}-1.x86_64.rpm" "$RPM"
echo "Wrote $RPM ($(du -h "$RPM" | cut -f1))"
