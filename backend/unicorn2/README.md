# [unicorn2](https://github.com/unicorn-engine/unicorn) backend

ARM emulator backend based on [Unicorn Engine 2](https://github.com/unicorn-engine/unicorn) (upstream `2.1.4` plus the patches in `src/main/native/patches/`). Supports emulating ARM32/ARM64 native libraries on macOS, Linux and Windows.

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
- `pkg-config` (`brew install pkgconf`), required by unicorn's `qemu/configure`
- Unicorn source is cloned and patched automatically by `build.sh`: the upstream tag `2.1.4` is
  cloned into `~/git/unicorn-2.1.4` and `patches/*.patch` are applied. `build.sh` refuses to build a
  tree that is not exactly upstream `2.1.4` plus these patches.

#### Why the patch

`patches/0001-apple-jit-state-for-hooks-in-foreign-runtimes.patch` only changes behaviour on Apple
Silicon. Unicorn 2.1.x caches the per-thread `MAP_JIT` write protection, skips
`pthread_jit_write_protect_np()` when the cache already matches, and restores the caller's state only
when the outermost API call returns, but HotSpot toggles the same state on every JNI transition. A
`uc_*` call made from a Java hook (e.g. `munmap` in a syscall handler, or a nested `emu_start`) then
patches translated code with the thread still in execute mode and dies with `SIGBUS` in
`do_tb_phys_invalidate`; and once that is avoided, the nested call returns to Java in write mode and
the JVM faults on its own code. The patch always applies the requested state and hands the thread
back in its entry state on every nesting level. Drop it once upstream unicorn ships an equivalent fix.

### Docker Cross-Compilation (Linux / Windows)

- [Docker](https://www.docker.com/) (with `docker buildx` multi-platform support)

Docker clones the upstream unicorn tag from GitHub, applies `patches/` and compiles it inside the container.

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

Set the `UNICORN_HOME` environment variable to specify a custom unicorn source path (defaults to `~/git/unicorn-2.1.4`):

```bash
UNICORN_HOME=/path/to/unicorn ./build.sh osx_arm64
```

Build artifacts are placed in `src/main/resources/natives/<platform>/`.
