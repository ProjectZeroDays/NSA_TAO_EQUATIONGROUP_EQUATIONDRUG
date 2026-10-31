#!/bin/bash
# packaging/dmg.sh — build .dmg for macOS VM
# Requires: hdiutil (macOS native), or create-dmg
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-2.3.1}
mkdir -p packaging/dmg/staging
cp build/peddlecheap packaging/dmg/staging/ 2>/dev/null || echo "No macOS binary; build on macOS VM"
cp -r README.md docs harness tests packaging/dmg/staging/

# If running on macOS with hdiutil
if command -v hdiutil >/dev/null 2>&1; then
    hdiutil create -volname "EquationDrug ${VERSION}" \
        -srcfolder packaging/dmg/staging \
        -ov -format UDZO "dist/equationdrug_${VERSION}.dmg"
    echo ".dmg built: dist/equationdrug_${VERSION}.dmg"
else
    echo ".dmg requires macOS VM with hdiutil; staging tree ready at packaging/dmg/staging/"
fi
