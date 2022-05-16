#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -m64 -arch arm64e -o ../../example_binaries/a12z_ios a12z.m -miphoneos-version-min=7.1 -framework Foundation && \
xcrun -sdk macosx clang -m64 -arch arm64 -o ../../example_binaries/a12z_osx a12z.m -mmacos-version-min=10.1 -framework Foundation
