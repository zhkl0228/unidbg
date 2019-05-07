#!/usr/bin/env bash
clang -o bootstrap32 bootstrap.m -lobjc -m32 -arch armv7 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1 -framework Foundation
clang -o bootstrap64 bootstrap.m -lobjc -m64 -arch arm64 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1 -framework Foundation
lipo -create bootstrap32 bootstrap64 -output bootstrap_objc
rm bootstrap32 bootstrap64

clang -o bootstrap32 bootstrap.c -lobjc -m32 -arch armv7 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1
clang -o bootstrap64 bootstrap.c -lobjc -m64 -arch arm64 --sysroot=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS11.4.sdk -miphoneos-version-min=7.1
lipo -create bootstrap32 bootstrap64 -output bootstrap
rm bootstrap32 bootstrap64
