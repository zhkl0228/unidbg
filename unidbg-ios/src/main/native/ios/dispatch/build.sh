#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -o libhookdispatch.dylib hook-dispatch.m -shared -m32 -arch armv7 -miphoneos-version-min=7.1 -F. -framework CydiaSubstrate && \
mv libhookdispatch.dylib libhookdispatch32.dylib && \
xcrun -sdk iphoneos clang -o libhookdispatch.dylib hook-dispatch.m -shared -m64 -arch arm64 -miphoneos-version-min=7.1 -F. -framework CydiaSubstrate && \
mv libhookdispatch.dylib libhookdispatch64.dylib && \
lipo -create libhookdispatch32.dylib libhookdispatch64.dylib -output libhookdispatch.dylib && \
rm libhookdispatch32.dylib libhookdispatch64.dylib && \
mv libhookdispatch.dylib ../../../resources/ios/lib/
