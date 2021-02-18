# Kvm backend

Allows you to emulate Android and iOS native library on Raspberry Pi 4B.<br>

Tested on [CentOS-7-aarch64](https://mirrors.bfsu.edu.cn/centos-altarch/7.9.2009/isos/aarch64/images/CentOS-Userland-7-aarch64-RaspberryPI-Minimal-4-2009-sda.raw.xz) with Raspberry Pi 4B.<br>

1. Download [CentOS-7](https://mirrors.bfsu.edu.cn/centos-altarch/7.9.2009/isos/aarch64/images/CentOS-Userland-7-aarch64-RaspberryPI-Minimal-4-2009-sda.raw.xz) and flash to TF card.
2. Boot Raspberry Pi 4B into CentOS-7 then compile kernel:<br>
   ` 0x0: yum install -y gcc gcc-c++ flex bison openssl-devel java-1.8.0-openjdk-devel maven git `<br>
   ` 0x1: git clone https://github.com/zhkl0228/linux `<br>
   ` 0x2: cd linux `<br>
   ` 0x3: git checkout rpi-5.4.y `<br>
   ` 0x4: make bcm2711_defconfig `<br>
   ` 0x5: make -j4 `<br>
   ` 0x6: make Image modules dtbs `<br>
   ` 0x7: make modules_install `<br>
   ` 0x8: cp arch/arm64/boot/dts/broadcom/bcm2711-rpi-4-b.dtb /boot/ `<br>
   ` 0x9: /usr/bin/cp -f arch/arm64/boot/dts/overlays/*.dtb* /boot/overlays/ `<br>
   ` 0xa: cp arch/arm64/boot/Image /boot/kernel8.img `<br>
   ` 0xb: reboot `<br>
