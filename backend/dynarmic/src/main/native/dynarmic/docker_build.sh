#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../../resources/natives/linux_64"
IMAGE_NAME="unidbg-dynarmic-builder"

cd "$SCRIPT_DIR"

echo "Building Docker image (first build may take 30-60 min under QEMU)..."
docker build --platform linux/amd64 -t "$IMAGE_NAME" .

echo "Extracting libdynarmic.so..."
mkdir -p "$OUTPUT_DIR"
CONTAINER_ID=$(docker create "$IMAGE_NAME")
docker cp "$CONTAINER_ID:/build/jni/build/libdynarmic.so" "$OUTPUT_DIR/libdynarmic.so"
docker rm "$CONTAINER_ID" > /dev/null

echo "Done: $OUTPUT_DIR/libdynarmic.so"
ls -l "$OUTPUT_DIR/libdynarmic.so"
