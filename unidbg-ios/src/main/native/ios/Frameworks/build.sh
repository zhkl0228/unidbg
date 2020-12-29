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

build_UIKit UIKit "Foundation"
build_framework JavaScriptCore "Foundation"
build_framework MultipeerConnectivity "Foundation"
build_framework PushKit "Foundation"
build_framework WebKit "Foundation"
build_framework AdSupport "Foundation"
build_framework Photos "Foundation"
build_framework ExternalAccessory "Foundation"
build_framework AddressBookUI "Foundation"
build_framework AddressBook "Foundation"
build_framework CoreLocation "Foundation"
build_framework AVFoundation "Foundation"
build_framework AudioToolbox "Foundation"
build_framework CoreMotion "CoreFoundation"
build_framework GLKit "Foundation"
build_framework MediaPlayer "Foundation"
build_framework SceneKit "Foundation"
build_framework Metal "Foundation"
build_framework SystemConfiguration "CoreFoundation"
build_framework CoreTelephony "CoreFoundation"
build_framework PassKit "Foundation"
build_framework Contacts "Foundation"
build_framework AssetsLibrary "Foundation"
build_framework GSS "Foundation"
build_framework Security "CoreFoundation"
build_framework CFNetwork "CoreFoundation"
build_CoreGraphics CoreGraphics "CoreFoundation"
build_framework Accelerate "Foundation"
build_framework VideoToolbox "Foundation"
build_framework CoreText "CoreFoundation"
build_framework MobileCoreServices "CoreFoundation"
build_framework CoreImage "CoreFoundation"
build_framework ImageIO "Foundation"
build_framework CoreVideo "CoreFoundation"
build_framework CoreMedia "CoreFoundation"
build_framework QuartzCore "CoreFoundation"
build_framework OpenGLES "CoreFoundation"
build_framework IOKit "CoreFoundation"
build_framework UserNotifications "Foundation"
build_framework AVKit "Foundation"
build_framework CoreAudio "CoreFoundation"
build_framework CloudKit "Foundation"
build_framework CoreData "CoreFoundation"
build_framework QuickLook "Foundation"
build_framework LocalAuthentication "Foundation"
build_framework MapKit "Foundation"
build_framework MessageUI "Foundation"
build_framework SafariServices "Foundation"
build_framework ReplayKit "Foundation"
build_framework CoreSpotlight "Foundation"
build_framework EventKit "Foundation"
build_framework MediaAccessibility "Foundation"
build_framework MediaToolbox "Foundation"
build_framework OpenAL "Foundation"
build_framework StoreKit "Foundation"
build_framework EventKitUI "Foundation"
build_framework CoreML "Foundation"
build_framework Vision "Foundation"
build_framework MetalPerformanceShaders "Foundation"
build_framework PhotosUI "Foundation"
build_framework MetalKit "Foundation"
