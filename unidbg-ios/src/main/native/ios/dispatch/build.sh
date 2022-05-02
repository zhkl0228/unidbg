#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -o libhookdispatch.dylib hook-dispatch.m -shared -m64 -arch arm64 -miphoneos-version-min=7.1 -F. -framework CydiaSubstrate && \
mv libhookdispatch.dylib ../../../resources/ios/lib/
