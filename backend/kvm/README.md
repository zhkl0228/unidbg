# KVM backend

KVM-based ARM64 emulator backend for Linux ARM64 hosts (e.g. Raspberry Pi 4B). Uses the Linux KVM hypervisor to run guest ARM64 code natively.

## Supported Platforms

| Platform | Architecture | Output |
|----------|-------------|--------|
| Linux | ARM64 | `linux_arm64/libkvm.so` |

## Prerequisites

### Docker Build (recommended)

- [Docker](https://www.docker.com/) (with ARM64 platform support)

### Native Build

- Linux ARM64 host (e.g. Raspberry Pi 4B with CentOS-7-aarch64)
- GCC
- JDK (`JAVA_HOME` environment variable must be set)

### Kernel Setup (Raspberry Pi 4B)

Tested on [CentOS-7-aarch64](https://mirrors.bfsu.edu.cn/centos-altarch/7.9.2009/isos/aarch64/images/CentOS-Userland-7-aarch64-RaspberryPI-Minimal-4-2009-sda.raw.xz) with Raspberry Pi 4B.

1. Download [CentOS-7](https://mirrors.bfsu.edu.cn/centos-altarch/7.9.2009/isos/aarch64/images/CentOS-Userland-7-aarch64-RaspberryPI-Minimal-4-2009-sda.raw.xz) and flash to TF card.
2. Boot Raspberry Pi 4B into CentOS-7 with root password `centos`.
3. Resize/Expand the RootFS for the whole SD Card.
4. Compile kernel with KVM support:

```bash
yum install -y make gcc gcc-c++ flex bison openssl-devel java-1.8.0-openjdk-devel maven git
git clone https://github.com/zhkl0228/linux
cd linux && git checkout rpi-5.4.y
make bcm2711_defconfig
make -j4
make Image modules dtbs
make modules_install
cp arch/arm64/boot/dts/broadcom/bcm2711-rpi-4-b.dtb /boot/
cp -f arch/arm64/boot/dts/overlays/*.dtb* /boot/overlays/
cp arch/arm64/boot/Image /boot/kernel8.img
reboot
```

## Build

All builds are performed via a single `build.sh` script located in `src/main/native/`:

```bash
cd backend/kvm/src/main/native

# Build via Docker (default, works on any host)
./build.sh docker

# Build natively (requires Linux ARM64 host)
./build.sh native

# Clean Docker build (--no-cache)
./build.sh --clean docker
```

Build artifacts are placed in `src/main/resources/natives/linux_arm64/`.
