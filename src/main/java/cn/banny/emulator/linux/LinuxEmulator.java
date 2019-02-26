package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;

public interface LinuxEmulator extends Emulator {

    int EPERM = 1;
    int EBADF = 9;
    int EAGAIN = 11;
    int ENOMEM = 12;
    int EACCES = 13;
    int EFAULT = 14;
    int EINVAL = 22;
    int ENOTTY = 25;
    int ENOSYS = 38;
    int EAFNOSUPPORT = 97;
    int ECONNREFUSED = 111;

}
