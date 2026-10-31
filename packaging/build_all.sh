#!/bin/bash
# packaging/build_all.sh — master packaging script for release creation
# Runs .deb (.snap), (.flatpak reference), (.dmg reference), (.ipa reference)
set -uo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo "2.3.1")}
echo "=== Building release artifacts for v${VERSION} ==="
bash packaging/deb.sh || echo "[NOTE] .deb requires Linux VM (dpkg-deb)"
bash packaging/snap.sh || echo "[NOTE] .snap requires snapcraft on VM"
bash packaging/flatpak.sh || echo "[NOTE] .flatpak requires flatpak-builder"
bash packaging/dmg.sh || echo "[NOTE] .dmg requires macOS VM (hdiutil)"
bash packaging/ipa.sh || echo "[NOTE] .ipa requires Xcode on macOS VM"
echo "=== Artifacts in dist/ ==="
ls -la dist/ 2>/dev/null || echo "(none yet — run individual packaging scripts on target VMs)"
echo "=== Complete ==="
