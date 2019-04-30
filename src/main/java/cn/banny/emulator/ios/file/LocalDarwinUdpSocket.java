package cn.banny.emulator.ios.file;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.unix.UnixEmulator;
import cn.banny.emulator.unix.file.LocalUdpSocket;

public class LocalDarwinUdpSocket extends LocalUdpSocket {

    public LocalDarwinUdpSocket(Emulator emulator) {
        super(emulator);
    }

    @Override
    protected int connect(String path) {
        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }
}
