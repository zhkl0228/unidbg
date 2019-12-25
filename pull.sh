#!/usr/bin/env sh

mkdir dev
adb shell cat /dev/__properties__ > dev/__properties__

mkdir -p system/usr/share/zoneinfo
adb pull /system/usr/share/zoneinfo/tzdata system/usr/share/zoneinfo

mkdir lib
adb pull /system/lib/libc.so lib
adb pull /system/lib/libc++.so lib/libcpp.so
adb pull /system/lib/libdl.so lib
adb pull /system/lib/liblog.so lib
adb pull /system/lib/libm.so lib
adb pull /system/lib/libstdc++.so lib/libstdcpp.so
adb pull /system/lib/libz.so lib
adb pull /system/lib/libcrypto.so lib
adb pull /system/lib/libssl.so lib

set -e

mkdir lib64
adb pull /system/lib64/libc.so lib64
adb pull /system/lib64/libc++.so lib64/libcpp.so
adb pull /system/lib64/libdl.so lib64
adb pull /system/lib64/liblog.so lib64
adb pull /system/lib64/libm.so lib64
adb pull /system/lib64/libstdc++.so lib64/libstdcpp.so
adb pull /system/lib64/libz.so lib64
adb pull /system/lib64/libcrypto.so lib64
adb pull /system/lib64/libssl.so lib64
