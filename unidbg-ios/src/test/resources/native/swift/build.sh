#!/usr/bin/env bash
set -e

xcrun -sdk iphoneos swiftc -module-name swift_library -target arm64-apple-ios11.0 -parse-as-library -swift-version 4 \
      -emit-objc-header -emit-objc-header-path swift_library-Swift.h swift_library.swift -c -o swift_library.o && \
xcrun -sdk iphoneos clang -m64 -arch arm64 -o ../../example_binaries/swift_test swift.m swift_library.o -miphoneos-version-min=11.0 \
      -framework Foundation -L/usr/lib/swift -Wl,-rpath,/usr/lib/swift \
      -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/iphoneos
