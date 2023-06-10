JAVA_INC="$JAVA_HOME"/include
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

# Docker path
DYNARMIC_HOME=/github/dynarmic

c++  -m64 -o libdynarmic.so -shared -fPIC -std=c++17 -O2 \
  -I $DYNARMIC_HOME/src -I $DYNARMIC_HOME/externals/fmt/include dynarmic.cpp arm_dynarmic_cp15.cpp \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -DDYNARMIC_MASTER \
  $DYNARMIC_HOME/build/src/dynarmic/libdynarmic.a \
  $DYNARMIC_HOME/build/externals/zydis/libZydis.a \
  $DYNARMIC_HOME/build/externals/mcl/src/libmcl.a \
  $DYNARMIC_HOME/build/externals/fmt/libfmt.a && \

mv libdynarmic.so ../../resources/natives/linux_64/
