JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

"$JAVA_HOME"/bin/javah -cp ../../../../target/classes com.github.unidbg.arm.backend.kvm.Kvm && \
  gcc -m64 -o libkvm.so -shared -O2 \
  kvm.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" && \
  mv libkvm.so ../../resources/natives/linux_arm64
