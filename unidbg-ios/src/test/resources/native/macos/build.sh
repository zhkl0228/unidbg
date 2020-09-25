#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -m32 -arch armv7 -o a12z_ios a12z.m -framework Foundation && \
mv a12z_ios a12z_ios32 && \
xcrun -sdk iphoneos clang -m64 -arch arm64 -o a12z_ios a12z.m -framework Foundation && \
mv a12z_ios a12z_ios64 && \
lipo -create a12z_ios32 a12z_ios64 -output ../../example_binaries/a12z_ios && \
rm a12z_ios32 a12z_ios64
xcrun -sdk macosx clang -m64 -arch arm64 -o ../../example_binaries/a12z_osx a12z.m -framework Foundation
