#!/bin/sh
set -e
export KERNEL_VERSION=$(uname -r)
export SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

cd "$SCRIPT_DIR"

export BUILD_DIR="$SCRIPT_DIR/build"
rm -rf "$BUILD_DIR"

if [ ! -d "kernel-hook-framework" ]; then
    echo "kernel-hook-framework not exist, clone it"
    git clone https://github.com/WeiJiLab/kernel-hook-framework
fi

cd "$SCRIPT_DIR/kernel-hook-framework/src"
if [ -z "$(grep simplify_symbols /proc/kallsyms)" ]; then
  make arm64 KDIR="/lib/modules/$KERNEL_VERSION/build" HAS_NO_SIMPLIFY_SYMBOLS=1
else
  make arm64 KDIR="/lib/modules/$KERNEL_VERSION/build"
fi
cd "$SCRIPT_DIR"

#Build HCR Driver
INCLUDE_DIR="$SCRIPT_DIR/include"
if [ -L "$INCLUDE_DIR" ] || [ -e "$INCLUDE_DIR" ]; then
  rm -f "$INCLUDE_DIR"
fi
ln -s "$SCRIPT_DIR/kernel-hook-framework/sample/include" "$INCLUDE_DIR"
make
rm -f "$INCLUDE_DIR"

cd "$BUILD_DIR"
mv "$SCRIPT_DIR/kernel-hook-framework/src/hookFrame.ko" .

echo "Build finished, please insmod drivers in build folder ( *.ko )."
ls -l "$BUILD_DIR"