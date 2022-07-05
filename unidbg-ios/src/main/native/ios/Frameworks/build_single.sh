#!/usr/bin/env bash
set -e

# -Wl,-install_name,/System/Library/Frameworks/"$1".framework/Versions/A/"$1"
# -Wl,-install_name,/System/Library/Frameworks/"$1".framework/"$1"

function build_framework() {
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m32 -arch armv7 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"32 && \
  xcrun -sdk iphoneos clang -o "$1"/"$1" "$1"/"$1".m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework "$2" && \
  mv "$1"/"$1" "$1"/"$1"64 && \
  lipo -create "$1"/"$1"32 "$1"/"$1"64 -output "$1"/"$1" && \
  rm "$1"/"$1"32 "$1"/"$1"64 && \
  mkdir -p ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework && \
  mv "$1"/"$1" ../../../resources/ios/7.1/System/Library/Frameworks/"$1".framework/
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

build_framework AppTrackingTransparency "Foundation"
build_framework AuthenticationServices "Foundation"
build_framework BackgroundTasks "Foundation"
build_framework Combine "Foundation"
build_framework CryptoKit "Foundation"
build_framework MetricKit "Foundation"
build_framework NaturalLanguage "Foundation"
build_framework SoundAnalysis "Foundation"
build_framework SwiftUI "Foundation"
build_framework WidgetKit "Foundation"
