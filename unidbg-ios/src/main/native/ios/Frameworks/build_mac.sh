#!/usr/bin/env bash
set -e

# -Wl,-install_name,/System/Library/Frameworks/"$1".framework/Versions/A/"$1"
# -Wl,-install_name,/System/Library/Frameworks/"$1".framework/"$1"

function build_framework() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
}
function build_framework_version_a() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m32 -arch armv7 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"32 && \
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"64 && \
  lipo -create "$1"/"$1"32 "$1"/"$1"64 -output "$1"/"$1" && \
  rm "$1"/"$1"32 "$1"/"$1"64 && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/Versions/A && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/Versions/A/
}
function build_CoreGraphics() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m "$1"/spng.c -shared -lobjc -lz -m32 -arch armv7 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"32 && \
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m "$1"/spng.c -shared -lobjc -lz -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"64 && \
  lipo -create "$1"/"$1"32 "$1"/"$1"64 -output "$1"/"$1" && \
  rm "$1"/"$1"32 "$1"/"$1"64 && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
}
function build_UIKit() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m32 -arch armv7 -miphoneos-version-min=7.1 -framework "$2" \
  -framework CoreGraphics -framework AdSupport -framework CoreTelephony && \
  mv "$1"/"$1" "$1"/"$1"32 && \
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" \
  -framework CoreGraphics -framework AdSupport -framework CoreTelephony && \
  mv "$1"/"$1" "$1"/"$1"64 && \
  lipo -create "$1"/"$1"32 "$1"/"$1"64 -output "$1"/"$1" && \
  rm "$1"/"$1"32 "$1"/"$1"64 && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
}

build_framework AppKit "Foundation"
build_framework Quartz "Foundation"
build_framework Carbon "Foundation"
build_framework Cocoa "Foundation"
build_framework CoreServices "CoreFoundation"
build_framework ApplicationServices "Foundation"
build_framework CoreWLAN "Foundation"
build_framework AudioUnit "Foundation"
build_framework OpenGL "Foundation"
build_framework ServiceManagement "Foundation"
