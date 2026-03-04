#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/../resources/natives"
IMAGE_NAME="unidbg-kvm-builder"

CLEAN=false
while [[ "$1" == --* ]]; do
    case "$1" in
        --clean) CLEAN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$SCRIPT_DIR"

build_docker() {
    echo "=== Building for linux_arm64 (Docker) ==="

    local docker_args=""
    if $CLEAN; then
        docker_args="--no-cache"
    fi

    docker build $docker_args -t "$IMAGE_NAME" .

    echo "Extracting libkvm.so..."
    mkdir -p "$RESOURCES_DIR/linux_arm64"
    CONTAINER_ID=$(docker create "$IMAGE_NAME")
    docker cp "$CONTAINER_ID:/build/build/libkvm.so" "$RESOURCES_DIR/linux_arm64/libkvm.so"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/linux_arm64/libkvm.so"
    ls -l "$RESOURCES_DIR/linux_arm64/libkvm.so"
}

build_native() {
    echo "=== Building for linux_arm64 (native) ==="

    JAVA_INC="$(realpath "$JAVA_HOME"/include)"
    JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

    gcc -o libkvm.so -fPIC -shared -O2 \
      kvm.c \
      -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC"

    mkdir -p "$RESOURCES_DIR/linux_arm64"
    mv libkvm.so "$RESOURCES_DIR/linux_arm64/"

    echo "Done: $RESOURCES_DIR/linux_arm64/libkvm.so"
    ls -l "$RESOURCES_DIR/linux_arm64/libkvm.so"
}

TARGET=${1:-docker}

case "$TARGET" in
    docker)
        build_docker
        ;;
    native)
        build_native
        ;;
    *)
        echo "Usage: $0 [--clean] [docker|native]"
        echo ""
        echo "Options:"
        echo "  --clean   Clean build (Docker: --no-cache)"
        echo ""
        echo "Targets:"
        echo "  docker    Build via Docker (default, works on any host)"
        echo "  native    Build natively (requires Linux ARM64 host)"
        exit 1
        ;;
esac
