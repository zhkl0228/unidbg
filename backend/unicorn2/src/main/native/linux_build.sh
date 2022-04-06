# git clone https://github.com/zhkl0228/unicorn
# UNICORN_ARCHS="arm aarch64" UNICORN_STATIC=yes ./make.sh

JAVA_INC="$JAVA_HOME"/include
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

UNICORN_HOME=~/git/unicorn

gcc -o libunicorn.so -shared -O3 -DNDEBUG \
  -I $UNICORN_HOME/include unicorn.c sample_arm.c sample_arm64.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -fPIC \
  $UNICORN_HOME/libunicorn.a &&
  mv libunicorn.so ../resources/natives/linux_64/
