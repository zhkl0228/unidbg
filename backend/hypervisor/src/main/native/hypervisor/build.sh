#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/../../resources/natives"

cd "$SCRIPT_DIR"

echo "=== Building for osx_arm64 ==="

JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

xcrun -sdk macosx clang++ -arch arm64 -o libhypervisor.dylib -lobjc -shared -std=c++17 -O2 \
  -mmacosx-version-min=11.0 \
  -framework Hypervisor hypervisor.mm \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC"

mkdir -p "$RESOURCES_DIR/osx_arm64"
mv libhypervisor.dylib "$RESOURCES_DIR/osx_arm64/"

echo "Done: $RESOURCES_DIR/osx_arm64/libhypervisor.dylib"
ls -l "$RESOURCES_DIR/osx_arm64/libhypervisor.dylib"
