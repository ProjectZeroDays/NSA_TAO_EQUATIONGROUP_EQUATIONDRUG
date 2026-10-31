#!/bin/bash
# packaging/flatpak.sh — build flatpak for Linux VM
# Requires: flatpak-builder, meson/ninja, python3
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-2.3.1}
mkdir -p packaging/flatpak

cat > packaging/flatpak/org.projectzero.equationdrug.json <<EOF
{
  "app-id": "org.projectzero.equationdrug",
  "runtime": "org.freedesktop.Platform",
  "runtime-version": "22.08",
  "sdk": "org.freedesktop.Sdk",
  "command": "peddlecheap",
  "finish-args": ["--share=network", "--filesystem=host"],
  "modules": [
    {
      "name": "equationdrug",
      "buildsystem": "simple",
      "build-commands": ["make build/peddlecheap build/mscfg32.dll"],
      "sources": [{"type":"dir","path":".."}]
    }
  ]
}
EOF

echo "flatpak manifest: packaging/flatpak/org.projectzero.equationdrug.json"
echo "run: flatpak-builder --force-clean build/flatpak packaging/flatpak/org.projectzero.equationdrug.json"
