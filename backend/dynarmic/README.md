# [dynarmic](https://github.com/zhkl0228/yuzu-dynarmic) backend

ARM dynamic recompiler backend based on [yuzu-dynarmic](https://github.com/zhkl0228/yuzu-dynarmic). Supports emulating ARM32/ARM64 native libraries on macOS, Linux and Windows.

## Supported Platforms

| Platform | Architecture | Output |
|----------|-------------|--------|
| macOS | ARM64 | `osx_arm64/libdynarmic.dylib` |
| macOS | x86_64 | `osx_64/libdynarmic.dylib` |
| Linux | x86_64 | `linux_64/libdynarmic.so` |
| Linux | ARM64 | `linux_arm64/libdynarmic.so` |
| Windows | x86_64 | `windows_64/dynarmic.dll` |

## Prerequisites

### macOS Native Build

- Xcode Command Line Tools
- JDK (`JAVA_HOME` environment variable must be set)
- dynarmic source and pre-built static libraries:

```bash
# Clone dynarmic
git clone --recursive https://github.com/zhkl0228/yuzu-dynarmic ~/git/dynarmic

# Build ARM64 static libraries
cd ~/git/dynarmic
mkdir -p build_arm64 && cd build_arm64
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
         -DDYNARMIC_TESTS=OFF \
         -DDYNARMIC_WARNINGS_AS_ERRORS=OFF \
         -DDYNARMIC_USE_BUNDLED_EXTERNALS=ON
make -j$(sysctl -n hw.ncpu)

# Build x86_64 static libraries (cross-compile)
cd ~/git/dynarmic
mkdir -p build_x86_64 && cd build_x86_64
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_OSX_ARCHITECTURES=x86_64 \
         -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
         -DDYNARMIC_TESTS=OFF \
         -DDYNARMIC_WARNINGS_AS_ERRORS=OFF \
         -DDYNARMIC_USE_BUNDLED_EXTERNALS=ON
make -j$(sysctl -n hw.ncpu)
```

### Docker Cross-Compilation (Linux / Windows)

- [Docker](https://www.docker.com/) (with `docker buildx` multi-platform support)

Docker automatically clones the dynarmic source from GitHub and compiles it inside the container. No local pre-build is required.

## Build

All builds are performed via a single `build.sh` script located in `src/main/native/dynarmic/`:

```bash
cd backend/dynarmic/src/main/native/dynarmic

# Build all platforms
./build.sh all

# Build macOS only (ARM64 + x86_64)
./build.sh osx

# Build a single macOS target
./build.sh osx_arm64
./build.sh osx_64

# Build all Docker targets (Linux + Windows)
./build.sh docker

# Build a single Docker target
./build.sh linux_64
./build.sh linux_arm64
./build.sh windows_64
```

Set the `DYNARMIC_HOME` environment variable to specify a custom dynarmic source path (defaults to `~/git/dynarmic`):

```bash
DYNARMIC_HOME=/path/to/dynarmic ./build.sh osx_arm64
```

Build artifacts are placed in `src/main/resources/natives/<platform>/`.

## Directory Structure

```
src/main/native/dynarmic/
├── build.sh                 # Unified build script
├── Dockerfile               # Linux cross-compilation (CentOS 7)
├── Dockerfile.windows       # Windows cross-compilation (MinGW)
├── CMakeLists.txt           # CMake config for JNI build inside Docker
├── dynarmic.cpp             # JNI implementation
├── arm_dynarmic_cp15.cpp    # CP15 coprocessor implementation
└── mman.c                   # Windows mmap compatibility layer
```
