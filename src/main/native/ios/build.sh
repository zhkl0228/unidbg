#!/usr/bin/env bash
set -e

clang -o bootstrap bootstrap.m -lobjc -m32 -arch armv7 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1 -framework Foundation
mv bootstrap bootstrap32
clang -o bootstrap bootstrap.m -lobjc -m64 -arch arm64 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1 -framework Foundation
mv bootstrap bootstrap64
lipo -create bootstrap32 bootstrap64 -output bootstrap_objc
rm bootstrap32 bootstrap64
mv bootstrap_objc ../../resources/ios/

clang -o bootstrap bootstrap.c -lobjc -m32 -arch armv7 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1
mv bootstrap bootstrap32
clang -o bootstrap bootstrap.c -lobjc -m64 -arch arm64 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1
mv bootstrap bootstrap64
lipo -create bootstrap32 bootstrap64 -output bootstrap
rm bootstrap32 bootstrap64
mv bootstrap ../../resources/ios/

clang -o libclassdump.dylib class-dump.m -shared -lobjc -m32 -arch armv7 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1 -framework Foundation
mv libclassdump.dylib libclassdump32.dylib
clang -o libclassdump.dylib class-dump.m -shared -lobjc -m64 -arch arm64 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1 -framework Foundation
mv libclassdump.dylib libclassdump64.dylib
lipo -create libclassdump32.dylib libclassdump64.dylib -output libclassdump.dylib
rm libclassdump32.dylib libclassdump64.dylib
mv libclassdump.dylib ../../resources/ios/lib/
