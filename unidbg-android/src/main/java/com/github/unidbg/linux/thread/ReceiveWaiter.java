package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.linux.file.SocketIO;
import com.github.unidbg.thread.AbstractWaiter;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class ReceiveWaiter extends AbstractWaiter {
    private final Thread thread;
    private int ret;

    public ReceiveWaiter(FileIO file, Backend backend, Pointer buf, int len, int flags,
                         Pointer src_addr, Pointer addrlen) {
        this.thread = new Thread(() -> {
            ret = file.recvfrom(backend, buf, len, flags, src_addr, addrlen);
        });
        this.thread.start();
    }

    @Override
    public void onContinueRun(Emulator<?> emulator) {
        emulator.getBackend().reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_R0 : Arm64Const.UC_ARM64_REG_X0,
                ret);
    }

    @Override
    public boolean canDispatch() {
        if (this.thread.getState() == Thread.State.TERMINATED)
            return true;
        Thread.yield();
        return false;
    }
}
