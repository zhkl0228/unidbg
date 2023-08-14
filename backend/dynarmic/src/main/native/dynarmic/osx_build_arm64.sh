JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

DYNARMIC_HOME=~/git/dynarmic

"$(/usr/libexec/java_home -v 1.8)"/bin/javah -cp ../../../../target/classes com.github.unidbg.arm.backend.dynarmic.Dynarmic && \
  xcrun -sdk macosx clang++ -m64 -o libdynarmic.dylib -shared -std=c++20 -O2 -mmacosx-version-min=13.0 \
  -I $DYNARMIC_HOME/src -I$DYNARMIC_HOME/externals/catch/include dynarmic.cpp arm_dynarmic_cp15.cpp \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -DDYNARMIC_MASTER \
  $DYNARMIC_HOME/build/src/dynarmic/libdynarmic.a \
  $DYNARMIC_HOME/build/externals/mcl/src/libmcl.a \
  $DYNARMIC_HOME/build/externals/fmt/libfmt.a && \
  mv libdynarmic.dylib ../../resources/natives/osx_arm64/
