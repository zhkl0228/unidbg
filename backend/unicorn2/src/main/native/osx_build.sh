JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

UNICORN_HOME=~/git/unicorn

"$(/usr/libexec/java_home -v 1.8)"/bin/javah -cp ../../../target/classes com.github.unidbg.arm.backend.unicorn.Unicorn && \
  xcrun -sdk macosx clang -m64 -o libunicorn.dylib -shared -O2 \
  -I $UNICORN_HOME/include unicorn.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
  $UNICORN_HOME/build/libaarch64-softmmu.a $UNICORN_HOME/build/libarm-softmmu.a $UNICORN_HOME/build/libunicorn-common.a $UNICORN_HOME/build/libunicorn.a &&
  mv libunicorn.dylib ../resources/natives/osx_64
