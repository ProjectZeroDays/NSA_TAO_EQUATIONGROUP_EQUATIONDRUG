#!/bin/bash
# packaging/deb.sh — build .deb for Debian/Ubuntu VM
# Requires: dpkg-deb, gcc, make, python3
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-2.3.1}
ARCH=${ARCH:-amd64}
PKG="equationdrug-${VERSION}-${ARCH}"
mkdir -p "packaging/debian/${PKG}/DEBIAN" "packaging/debian/${PKG}/usr/bin" \
         "packaging/debian/${PKG}/usr/share/equationdrug" \
         "packaging/debian/${PKG}/usr/lib/equationdrug"

cp build/peddlecheap "packaging/debian/${PKG}/usr/bin/"
cp build/mscfg32.dll "packaging/debian/${PKG}/usr/lib/equationdrug/" 2>/dev/null || true
cp -r harness tests include docs assets "packaging/debian/${PKG}/usr/share/equationdrug/"
cp README.md LICENSE PROVENANCE.md CHANGELOG.md "packaging/debian/${PKG}/usr/share/equationdrug/"

cat > "packaging/debian/${PKG}/DEBIAN/control" <<EOF
Package: equationdrug
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Depends: libc6, libgcc1, libstdc++6, python3, gcc
Maintainer: ProjectZeroDays <repo@example>
Description: EquationDrug / PeddleCheap protocol reconstruction toolkit
 Parity reimplementation of NSA TAO Equation Group tooling.
 Includes harness, crypto primes (AES/RC5/SHA-1/bignum), plugin host,
 and protocol validation against leaked artifacts.
EOF

dpkg-deb --build "packaging/debian/${PKG}" "dist/equationdrug_${VERSION}_${ARCH}.deb"
echo ".deb built: dist/equationdrug_${VERSION}_${ARCH}.deb"
