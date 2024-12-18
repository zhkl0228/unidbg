#!/usr/bin/env bash
set -e

function build_framework() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m32 -arch armv7 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"32 && \
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"64 && \
  lipo -create "$1"/"$1"32 "$1"/"$1"64 -output "$1"/"$1" && \
  rm "$1"/"$1"32 "$1"/"$1"64 && \
  mkdir -p ../../../resources/ios/7.1/System/Library/PrivateFrameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/PrivateFrameworks/"$1".framework/
}

build_framework FindMyDevice "Foundation"
build_framework ManagedConfiguration "Foundation"
build_framework MobileSystemServices "Foundation"
build_framework CrashReporterSupport "Foundation"
