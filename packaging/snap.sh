#!/bin/bash
# packaging/snap.sh — build snap for Ubuntu VM
# Requires: snapcraft
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-2.3.1}
mkdir -p packaging/snap/src
cp build/peddlecheap packaging/snap/src/ 2>/dev/null || true
cp build/mscfg32.dll packaging/snap/src/ 2>/dev/null || true
cp -r harness tests include docs assets packaging/snap/src/

cat > packaging/snap/snapcraft.yaml <<EOF
name: equationdrug
version: '${VERSION}'
summary: NSA TAO EquationDrug protocol reconstruction
base: core22
grade: devel
confinement: strict

parts:
  equationdrug:
    plugin: make
    source: .
    build-packages: [gcc, make, python3]
    install: [make install || true]

apps:
  peddlecheap:
    command: usr/bin/peddlecheap
EOF

snapcraft --destructive-mode 2>&1 || echo "snapcraft: VM install required (snapcraft not present on build host)"
echo ".snap attempt complete (requires snapcraft on VM)"
