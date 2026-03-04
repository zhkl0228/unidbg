#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/../../resources/natives"
DYNARMIC_HOME="${DYNARMIC_HOME:-$HOME/git/dynarmic}"
IMAGE_NAME="unidbg-dynarmic-builder"

cd "$SCRIPT_DIR"

# --- macOS native builds ---

build_osx_arm64() {
    echo "=== Building for osx_arm64 (native) ==="

    JAVA_INC="$(realpath "$JAVA_HOME"/include)"
    JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"
    BUILD_DIR="$DYNARMIC_HOME/build_arm64"

    if [ ! -d "$BUILD_DIR" ]; then
        echo "Error: ARM64 build directory not found: $BUILD_DIR"
        echo "Please build dynarmic for ARM64 first:"
        echo "  cd $DYNARMIC_HOME && mkdir -p build_arm64 && cd build_arm64"
        echo "  cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 ..."
        exit 1
    fi

    xcrun -sdk macosx clang++ -arch arm64 -o libdynarmic.dylib -shared -std=c++20 -O2 \
      -mmacosx-version-min=13.0 \
      -I "$DYNARMIC_HOME/src" \
      -I "$DYNARMIC_HOME/externals/fmt/include" \
      -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
      -DDYNARMIC_MASTER \
      dynarmic.cpp arm_dynarmic_cp15.cpp \
      "$BUILD_DIR/src/dynarmic/libdynarmic.a" \
      "$BUILD_DIR/externals/mcl/src/libmcl.a" \
      "$BUILD_DIR/externals/fmt/libfmt.a"

    mkdir -p "$RESOURCES_DIR/osx_arm64"
    mv libdynarmic.dylib "$RESOURCES_DIR/osx_arm64/"

    echo "Done: $RESOURCES_DIR/osx_arm64/libdynarmic.dylib"
    ls -l "$RESOURCES_DIR/osx_arm64/libdynarmic.dylib"
    echo
}

build_osx_64() {
    echo "=== Building for osx_64 (cross-compile x86_64) ==="

    JAVA_INC="$(realpath "$JAVA_HOME"/include)"
    JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"
    BUILD_DIR="$DYNARMIC_HOME/build_x86_64"

    if [ ! -d "$BUILD_DIR" ]; then
        echo "Error: x86_64 build directory not found: $BUILD_DIR"
        echo "Please build dynarmic for x86_64 first:"
        echo "  cd $DYNARMIC_HOME && mkdir -p build_x86_64 && cd build_x86_64"
        echo "  cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=x86_64 ..."
        exit 1
    fi

    xcrun -sdk macosx clang++ -arch x86_64 -o libdynarmic.dylib -shared -std=c++20 -O2 \
      -mmacosx-version-min=10.15 \
      -I "$DYNARMIC_HOME/src" \
      -I "$DYNARMIC_HOME/externals/fmt/include" \
      -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
      -DDYNARMIC_MASTER \
      dynarmic.cpp arm_dynarmic_cp15.cpp \
      "$BUILD_DIR/src/dynarmic/libdynarmic.a" \
      "$BUILD_DIR/externals/mcl/src/libmcl.a" \
      "$BUILD_DIR/externals/fmt/libfmt.a" \
      "$BUILD_DIR/externals/zydis/libZydis.a"

    mkdir -p "$RESOURCES_DIR/osx_64"
    mv libdynarmic.dylib "$RESOURCES_DIR/osx_64/"

    echo "Done: $RESOURCES_DIR/osx_64/libdynarmic.dylib"
    ls -l "$RESOURCES_DIR/osx_64/libdynarmic.dylib"
    echo
}

# --- Docker builds (cross-compilation for Linux / Windows) ---

build_linux() {
    local platform=$1
    local output_dir=$2
    shift 2
    local extra_args="$@"

    echo "=== Building for $output_dir ($platform) ==="
    docker build --platform "$platform" $extra_args -t "${IMAGE_NAME}-${output_dir}" .

    echo "Extracting libdynarmic.so..."
    mkdir -p "$RESOURCES_DIR/$output_dir"
    CONTAINER_ID=$(docker create --platform "$platform" "${IMAGE_NAME}-${output_dir}")
    docker cp "$CONTAINER_ID:/build/jni/build/libdynarmic.so" "$RESOURCES_DIR/$output_dir/libdynarmic.so"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/$output_dir/libdynarmic.so"
    ls -l "$RESOURCES_DIR/$output_dir/libdynarmic.so"
    echo
}

build_windows() {
    echo "=== Building for windows_64 (MinGW cross-compilation) ==="
    docker build -f Dockerfile.windows -t "${IMAGE_NAME}-windows_64" .

    echo "Extracting dynarmic.dll..."
    mkdir -p "$RESOURCES_DIR/windows_64"
    CONTAINER_ID=$(docker create "${IMAGE_NAME}-windows_64")
    docker cp "$CONTAINER_ID:/build/jni/dynarmic.dll" "$RESOURCES_DIR/windows_64/dynarmic.dll"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/windows_64/dynarmic.dll"
    ls -l "$RESOURCES_DIR/windows_64/dynarmic.dll"
    echo
}

# --- Main ---

TARGET=${1:-all}

case "$TARGET" in
    osx_arm64)
        build_osx_arm64
        ;;
    osx_64)
        build_osx_64
        ;;
    osx)
        build_osx_arm64
        build_osx_64
        ;;
    linux_arm64)
        build_linux linux/arm64 linux_arm64 --build-arg DEVTOOLSET=devtoolset-10
        ;;
    linux_64)
        build_linux linux/amd64 linux_64
        ;;
    windows_64)
        build_windows
        ;;
    docker)
        build_linux linux/arm64 linux_arm64 --build-arg DEVTOOLSET=devtoolset-10
        build_linux linux/amd64 linux_64
        build_windows
        ;;
    all)
        build_osx_arm64
        build_osx_64
        build_linux linux/arm64 linux_arm64 --build-arg DEVTOOLSET=devtoolset-10
        build_linux linux/amd64 linux_64
        build_windows
        ;;
    *)
        echo "Usage: $0 [osx_arm64|osx_64|osx|linux_arm64|linux_64|windows_64|docker|all]"
        echo ""
        echo "Targets:"
        echo "  osx_arm64   - macOS ARM64 (native build, needs build_arm64)"
        echo "  osx_64      - macOS x86_64 (cross-compile, needs build_x86_64)"
        echo "  osx         - both macOS targets"
        echo "  linux_arm64 - Linux ARM64 (Docker)"
        echo "  linux_64    - Linux x86_64 (Docker)"
        echo "  windows_64  - Windows x86_64 (Docker + MinGW)"
        echo "  docker      - all Docker targets (linux + windows)"
        echo "  all         - all platforms (default)"
        exit 1
        ;;
esac
