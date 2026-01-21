JAVA_INC="$JAVA_HOME"/include
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

# Docker path
DYNARMIC_HOME=/git/dynarmic
UNIDBG_HOME=/git/unidbg

# compile dynarmic
cd $DYNARMIC_HOME && mkdir -p build
cd build 
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON ..
make

cd $UNIDBG_HOME/backend/dynarmic/src/main/native

c++  -m64 -o libdynarmic.so -shared -fPIC -std=c++17 -O2 \
  -I $DYNARMIC_HOME/src -I $DYNARMIC_HOME/externals/fmt/include dynarmic.cpp arm_dynarmic_cp15.cpp \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -DDYNARMIC_MASTER \
  $DYNARMIC_HOME/build/src/dynarmic/libdynarmic.a \
  $DYNARMIC_HOME/build/externals/zydis/libZydis.a \
  $DYNARMIC_HOME/build/externals/mcl/src/libmcl.a \
  $DYNARMIC_HOME/build/externals/fmt/libfmt.a && \

mv libdynarmic.so ../../resources/natives/linux_64/
