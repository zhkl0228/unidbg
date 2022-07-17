JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

UNICORN_HOME=~/git/unicorn

"$(/usr/libexec/java_home -v 1.8)"/bin/javah -cp ../../../target/classes com.github.unidbg.arm.backend.unicorn.Unicorn && \
  xcrun -sdk macosx clang -m64 -o libunicorn.dylib -shared -O3 -DNDEBUG -arch arm64 \
  -I $UNICORN_HOME/include unicorn.c sample_arm.c sample_arm64.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -fPIC \
  $UNICORN_HOME/build/libunicorn.a &&
  mv libunicorn.dylib ../resources/natives/osx_arm64/
