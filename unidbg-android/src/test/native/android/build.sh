#!/usr/bin/env bash
set -e

$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=./Application.mk
$NDK_HOME/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./library.mk NDK_APPLICATION_MK=./Application.mk
