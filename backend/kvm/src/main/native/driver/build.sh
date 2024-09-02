#!/bin/sh
set -e
export KERNEL_VERSION=$(uname -r)
export SCRIPT_DIR=$(cd `dirname "$0"`;pwd)

#Setup Script Folder
cd $SCRIPT_DIR

#Clear Build Folder
export BUILD_DIR=$SCRIPT_DIR/build
rm -rf $BUILD_DIR

#Get Hook Framework
#If kernel-hook-framework not exist, clone it
if [ ! -d "kernel-hook-framework" ]; then
    echo "kernel-hook-framework not exist, clone it"
    git clone https://github.com/WeiJiLab/kernel-hook-framework
fi

#Build Framework
cd $SCRIPT_DIR/kernel-hook-framework/src
#Check cat /proc/kallsyms | grep simplify_symbols is empty
if [ -z "$(cat /proc/kallsyms | grep simplify_symbols)" ]; then
  make arm64 KDIR=/lib/modules/$KERNEL_VERSION/build HAS_NO_SIMPLIFY_SYMBOLS=1
else
  make arm64 KDIR=/lib/modules/$KERNEL_VERSION/build
fi
cd $SCRIPT_DIR

#Build HRC Driver
INCLUDE_DIR=$SCRIPT_DIR/include
if [ -d "$INCLUDE_DIR" ]; then
  rm $INCLUDE_DIR
fi
ln -s $SCRIPT_DIR/kernel-hook-framework/sample/include $INCLUDE_DIR
make
rm $INCLUDE_DIR

#Copy Driver Files
cd $BUILD_DIR
mv $SCRIPT_DIR/kernel-hook-framework/src/hookFrame.ko .

echo "Build finished, please insmod drivers in build folder ( *.ko )."
ls -l $BUILD_DIR