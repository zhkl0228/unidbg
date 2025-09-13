#!/usr/bin/env bash
set -e

# -Wl,-install_name,/System/Library/Frameworks/"$1".framework/Versions/A/"$1"
# -Wl,-install_name,/System/Library/Frameworks/"$1".framework/"$1"

function build_framework() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
}
function build_CoreGraphics() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m "$1"/spng.c -shared -lobjc -lz -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
}
function build_UIKit() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m UIKit/CFNetwork.m UIKit/new_symbol.mm -shared -lstdc++ -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" \
  -framework CoreGraphics -framework AdSupport -framework CoreTelephony && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
}

build_UIKit UIKit "Foundation"
build_framework Security "CoreFoundation"
build_framework QuartzCore "CoreFoundation"
build_CoreGraphics CoreGraphics "CoreFoundation"
