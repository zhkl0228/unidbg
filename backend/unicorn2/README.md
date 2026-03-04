# [unicorn2](https://github.com/zhkl0228/unicorn) backend

ARM emulator backend based on [Unicorn Engine 2](https://github.com/zhkl0228/unicorn). Supports emulating ARM32/ARM64 native libraries on macOS, Linux and Windows.

## Supported Platforms

| Platform | Architecture | Output |
|----------|-------------|--------|
| macOS | ARM64 | `osx_arm64/libunicorn.dylib` |
| macOS | x86_64 | `osx_64/libunicorn.dylib` |
| Linux | x86_64 | `linux_64/libunicorn.so` |
| Linux | ARM64 | `linux_arm64/libunicorn.so` |
| Windows | x86_64 | `windows_64/unicorn.dll` |

## Prerequisites

### macOS Native Build

- Xcode Command Line Tools
- JDK (`JAVA_HOME` environment variable must be set)
- Unicorn source is cloned and built automatically by `build.sh`. To prepare manually:

```bash
git clone -b unicorn2 https://github.com/zhkl0228/unicorn ~/git/unicorn

# ARM64 static library
cd ~/git/unicorn
mkdir -p build_arm64 && cd build_arm64
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
         -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
         -DUNICORN_ARCH="arm;aarch64"
make -j$(sysctl -n hw.ncpu)

# x86_64 static library (cross-compile)
cd ~/git/unicorn
mkdir -p build_x86_64 && cd build_x86_64
cmake .. -DCMAKE_BUILD_TYPE=Release \
         -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
         -DCMAKE_OSX_ARCHITECTURES=x86_64 \
         -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
         -DUNICORN_ARCH="arm;aarch64"
make -j$(sysctl -n hw.ncpu)
```

### Docker Cross-Compilation (Linux / Windows)

- [Docker](https://www.docker.com/) (with `docker buildx` multi-platform support)

Docker automatically clones the unicorn source from GitHub and compiles it inside the container.

## Build

All builds are performed via a single `build.sh` script located in `src/main/native/`:

```bash
cd backend/unicorn2/src/main/native

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

# Clean build (rebuild from scratch)
./build.sh --clean osx
```

Set the `UNICORN_HOME` environment variable to specify a custom unicorn source path (defaults to `~/git/unicorn`):

```bash
UNICORN_HOME=/path/to/unicorn ./build.sh osx_arm64
```

Build artifacts are placed in `src/main/resources/natives/<platform>/`.
