# git clone https://github.com/zhkl0228/unicorn
# UNICORN_ARCHS="arm aarch64" UNICORN_STATIC=yes ./make.sh

JAVA_INC="$JAVA_HOME"/include
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

UNICORN_HOME=~/git/unicorn

gcc -m64 -o unicorn.dll -shared -O3 -static -DNDEBUG \
  -I $UNICORN_HOME/include unicorn.c sample_arm.c sample_arm64.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -fPIC \
  $UNICORN_HOME/unicorn.a &&
  mv unicorn.dll ../resources/natives/windows_64/
