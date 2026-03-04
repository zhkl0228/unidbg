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

TARGET=${1:-all}

case "$TARGET" in
    linux_arm64)
        build_platform linux/arm64 linux_arm64
        ;;
    linux_64)
        build_platform linux/amd64 linux_64
        ;;
    all)
        build_platform linux/arm64 linux_arm64
        build_platform linux/amd64 linux_64
        ;;
    *)
        echo "Usage: $0 [linux_arm64|linux_64|all]"
        exit 1
        ;;
esac
