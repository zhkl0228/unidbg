JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

"$(/usr/libexec/java_home -v 1.8)"/bin/javah -cp ../../../target/classes com.github.unidbg.arm.backend.unicorn.Unicorn && \
  xcrun -sdk macosx clang -m64 -o libunicorn.dylib -shared -O2 \
  -I ~/git/unicorn/include unicorn.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
  ~/git/unicorn/build/libaarch64-softmmu.a ~/git/unicorn/build/libarm-softmmu.a ~/git/unicorn/build/libunicorn-common.a ~/git/unicorn/build/libunicorn.a &&
  mv libunicorn.dylib ../resources/natives/osx_64
