#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/../../resources/natives"
IMAGE_NAME="unidbg-dynarmic-builder"

cd "$SCRIPT_DIR"

build_platform() {
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

TARGET=${1:-all}

case "$TARGET" in
    linux_arm64)
        build_platform linux/arm64 linux_arm64 --build-arg DEVTOOLSET=devtoolset-10
        ;;
    linux_64)
        build_platform linux/amd64 linux_64
        ;;
    windows_64)
        build_windows
        ;;
    all)
        build_platform linux/arm64 linux_arm64 --build-arg DEVTOOLSET=devtoolset-10
        build_platform linux/amd64 linux_64
        build_windows
        ;;
    *)
        echo "Usage: $0 [linux_arm64|linux_64|windows_64|all]"
        exit 1
        ;;
esac
