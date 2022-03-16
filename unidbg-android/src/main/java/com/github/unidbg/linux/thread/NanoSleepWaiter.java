package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.signal.SignalTask;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class NanoSleepWaiter extends AndroidWaiter {

    private final Emulator<?> emulator;
    private final Pointer rem;
    private final long waitMillis;
    private final long startWaitTimeInMillis;

    public NanoSleepWaiter(Emulator<?> emulator, Pointer rem, TimeSpec timeSpec) {
        this.emulator = emulator;
        this.rem = rem;

        this.waitMillis = timeSpec.toMillis();
        this.startWaitTimeInMillis = System.currentTimeMillis();

        if (this.waitMillis <= 0) {
            throw new IllegalStateException();
        }
    }

    private boolean onSignal;

    @Override
    public void onSignal(SignalTask task) {
        super.onSignal(task);

        onSignal = true;

        if (rem != null) {
            TimeSpec timeSpec = TimeSpec.createTimeSpec(emulator, rem);
            long elapsed = System.currentTimeMillis() - startWaitTimeInMillis;
            timeSpec.setMillis(waitMillis - elapsed);
        }
    }

    @Override
    public void onContinueRun(Emulator<?> emulator) {
        super.onContinueRun(emulator);

        if (onSignal) {
            emulator.getBackend().reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_R0 : Arm64Const.UC_ARM64_REG_X0, -UnixEmulator.EINTR);
        }
    }

    @Override
    public boolean canDispatch() {
        if (onSignal) {
            return true;
        }
        if (System.currentTimeMillis() - startWaitTimeInMillis >= waitMillis) {
            return true;
        }
        Thread.yield();
        return false;
    }

}
