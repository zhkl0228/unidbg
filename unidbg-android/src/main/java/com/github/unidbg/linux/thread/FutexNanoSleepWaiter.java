package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.AndroidSyscallHandler;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class FutexNanoSleepWaiter extends FutexWaiter {

    private final long waitMillis;
    private final long startWaitTimeInMillis;

    public FutexNanoSleepWaiter(Pointer uaddr, int val, TimeSpec timeSpec) {
        super(uaddr, val);

        this.waitMillis = timeSpec.toMillis();
        this.startWaitTimeInMillis = System.currentTimeMillis();

        if (this.waitMillis <= 0) {
            throw new IllegalStateException();
        }
    }

    @Override
    public boolean canDispatch() {
        boolean ret = super.canDispatch();
        if (ret) {
            return true;
        }
        if (System.currentTimeMillis() - startWaitTimeInMillis >= waitMillis) {
            return true;
        }
        Thread.yield();
        return false;
    }

    @Override
    protected void onContinueRunInternal(Emulator<?> emulator) {
        super.onContinueRunInternal(emulator);

        emulator.getBackend().reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_R0 : Arm64Const.UC_ARM64_REG_X0, -AndroidSyscallHandler.ETIMEDOUT);
    }

}
