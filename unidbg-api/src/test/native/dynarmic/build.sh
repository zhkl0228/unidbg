xcrun -sdk macosx clang++ -m64 -o ../../../../target/dynarmic -std=c++11 \
  -I ~/git/dynarmic/include main.cpp \
  ~/git/dynarmic/build/src/libdynarmic.a \
  ~/git/dynarmic/build/externals/fmt/libfmt.a && \
  ../../../../target/dynarmic
