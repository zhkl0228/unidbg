#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../resources/natives/linux_arm64"
IMAGE_NAME="unidbg-kvm-builder"

cd "$SCRIPT_DIR"

echo "Building Docker image..."
docker build -t "$IMAGE_NAME" .

echo "Extracting libkvm.so..."
mkdir -p "$OUTPUT_DIR"
CONTAINER_ID=$(docker create "$IMAGE_NAME")
docker cp "$CONTAINER_ID:/build/build/libkvm.so" "$OUTPUT_DIR/libkvm.so"
docker rm "$CONTAINER_ID" > /dev/null

echo "Done: $OUTPUT_DIR/libkvm.so"
ls -l "$OUTPUT_DIR/libkvm.so"
