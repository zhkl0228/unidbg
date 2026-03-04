#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/../resources/natives"
IMAGE_NAME="unidbg-unicorn2-builder"

cd "$SCRIPT_DIR"

build_platform() {
    local platform=$1
    local output_dir=$2

    echo "=== Building for $platform ==="
    docker build --platform "$platform" -t "${IMAGE_NAME}-${output_dir}" .

    echo "Extracting libunicorn.so..."
    mkdir -p "$RESOURCES_DIR/$output_dir"
    CONTAINER_ID=$(docker create --platform "$platform" "${IMAGE_NAME}-${output_dir}")
    docker cp "$CONTAINER_ID:/build/jni/build/libunicorn.so" "$RESOURCES_DIR/$output_dir/libunicorn.so"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/$output_dir/libunicorn.so"
    ls -l "$RESOURCES_DIR/$output_dir/libunicorn.so"
    echo
}

build_windows() {
    echo "=== Building for windows_64 (MinGW cross-compilation) ==="
    docker build -f Dockerfile.windows -t "${IMAGE_NAME}-windows_64" .

    echo "Extracting unicorn.dll..."
    mkdir -p "$RESOURCES_DIR/windows_64"
    CONTAINER_ID=$(docker create "${IMAGE_NAME}-windows_64")
    docker cp "$CONTAINER_ID:/build/jni/unicorn.dll" "$RESOURCES_DIR/windows_64/unicorn.dll"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/windows_64/unicorn.dll"
    ls -l "$RESOURCES_DIR/windows_64/unicorn.dll"
    echo
}

TARGET=${1:-all}

case "$TARGET" in
    linux_arm64)
        build_platform linux/arm64 linux_arm64
        ;;
    linux_64)
        build_platform linux/amd64 linux_64
        ;;
    windows_64)
        build_windows
        ;;
    all)
        build_platform linux/arm64 linux_arm64
        build_platform linux/amd64 linux_64
        build_windows
        ;;
    *)
        echo "Usage: $0 [linux_arm64|linux_64|windows_64|all]"
        exit 1
        ;;
esac
