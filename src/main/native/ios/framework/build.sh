#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos clang -o UIKit UIKit.m -shared -lobjc -m32 -arch armv7 -miphoneos-version-min=7.1 -framework Foundation && \
mv UIKit UIKit32 && \
xcrun -sdk iphoneos clang -o UIKit UIKit.m -shared -lobjc -m64 -arch arm64 -miphoneos-version-min=7.1 -framework Foundation && \
mv UIKit UIKit64 && \
lipo -create UIKit32 UIKit64 -output UIKit && \
rm UIKit32 UIKit64 && \
mv UIKit ../../../resources/ios/7.1/System/Library/Frameworks/UIKit.framework/
