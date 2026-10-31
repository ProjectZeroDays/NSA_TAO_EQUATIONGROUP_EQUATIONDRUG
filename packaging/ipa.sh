#!/bin/bash
# packaging/ipa.sh — stub for .ipa generation (not applicable to CLI toolkit)
# The repo produces CLI/research binaries (peddlecheap, harness), not an iOS app.
# This script provides the packaging skeleton if a future iOS port is built.
set -uo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-2.3.1}
echo ".ipa is not applicable to CLI/research binaries."
echo "For a future iOS port, build an Xcode project with these sources:"
echo "  - src/ (core C99) -> compiled as static lib"
echo "  - harness/ -> Swift/Obj-C wrapper"
echo "  - assets/logo.svg -> AppIcon assets"
echo "Then: xcodebuild -scheme EquationDrug -archivePath build/EquationDrug-${VERSION}.xcarchive"
echo "Then: xcrun -sdk iphoneos PackageApplication -v build/*.xcarchive/Products/Applications/*.app -o dist/EquationDrug_${VERSION}.ipa"
echo "Staging directory: packaging/ipa/ (empty — requires Xcode on macOS)"
