JAVA_INC="$JAVA_HOME"/include
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

c++ -m64 -o libdynarmic.so -shared -fPIC -std=c++17 -O2 \
  -I ~/git/dynarmic/include -I ~/git/dynarmic/externals/fmt/include dynarmic.cpp arm_dynarmic_cp15.cpp \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
  ~/git/dynarmic/build/src/libdynarmic.a \
  ~/git/dynarmic/build/externals/fmt/libfmt.a && \
  mv libdynarmic.so ../../resources/natives/linux_64/
