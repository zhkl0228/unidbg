# Apple Silicon Hypervisor backend

ARM64 emulator backend using the macOS Hypervisor.framework. Allows you to emulate Android and iOS ARM64 native libraries on Apple Silicon at near-native speed.

## Supported Platforms

| Platform | Architecture | Output |
|----------|-------------|--------|
| macOS | ARM64 (Apple Silicon) | `osx_arm64/libhypervisor.dylib` |

## Prerequisites

- Apple Silicon Mac (M1/M2/M3/M4)
- Xcode Command Line Tools
- JDK (`JAVA_HOME` environment variable must be set)

## Sign the Java Binary

The Hypervisor.framework requires a special entitlement. Sign the `java` binary before running:

```bash
cd backend/hypervisor/assets
sudo ./ldid -M -Shypervisor.entitlements "$JAVA_HOME"/bin/java
```

## Build

```bash
cd backend/hypervisor/src/main/native/hypervisor
./build.sh
```

Build artifacts are placed in `src/main/resources/natives/osx_arm64/`.
