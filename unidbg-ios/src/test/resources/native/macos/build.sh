#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -m64 -arch arm64 -o ../../example_binaries/a12z_ios a12z.c &&\
xcrun -sdk macosx clang -m64 -arch arm64 -o ../../example_binaries/a12z_osx a12z.c
