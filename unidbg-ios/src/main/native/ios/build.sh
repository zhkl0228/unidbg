#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang++ -o bootstrap bootstrap.mm -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 \
  -framework Foundation -framework CoreTelephony -framework CFNetwork -framework Security -framework AVFoundation \
  -framework UIKit -framework CoreFoundation -framework SystemConfiguration -framework CoreGraphics && \
mv bootstrap bootstrap_objc && \
mv bootstrap_objc ../../resources/ios/

xcrun -sdk iphoneos clang++ -o bootstrap bootstrap.cpp -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 && \
mv bootstrap ../../resources/ios/

xcrun -sdk iphoneos clang -o libclassdump.dylib class-dump.m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework Foundation && \
mv libclassdump.dylib ../../resources/ios/lib/
