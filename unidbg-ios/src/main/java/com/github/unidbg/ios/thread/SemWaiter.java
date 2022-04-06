package com.github.unidbg.ios.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.ios.DarwinSyscall;
import com.github.unidbg.thread.AbstractWaiter;
import com.github.unidbg.thread.Waiter;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Map;

public class SemWaiter extends AbstractWaiter implements Waiter {

    private final int sem;
    private final Map<Integer, Boolean> semaphoreMap;
    private final long waitMillis;
    private final long startWaitTimeInMillis;

    public SemWaiter(int sem, Map<Integer, Boolean> semaphoreMap) {
        this(sem, semaphoreMap, 0L, 0);
    }

    public SemWaiter(int sem, Map<Integer, Boolean> semaphoreMap, long tv_sec, int tv_nsec) {
        this.sem = sem;
        this.semaphoreMap = semaphoreMap;
        this.waitMillis = tv_sec * 1000L + tv_nsec / 1000L;
        this.startWaitTimeInMillis = System.currentTimeMillis();
    }

    private boolean timeout;

    @Override
    public boolean canDispatch() {
        Boolean val = semaphoreMap.remove(sem);
        if (val != null) {
            return true;
        }
        if (waitMillis > 0) {
            if (System.currentTimeMillis() - startWaitTimeInMillis >= waitMillis) {
                timeout = true;
                return true;
            }
            Thread.yield();
        }
        return false;
    }

    @Override
    public void onContinueRun(Emulator<?> emulator) {
        if (timeout) {
            Backend backend = emulator.getBackend();
            emulator.getMemory().setErrno(DarwinSyscall.ETIMEDOUT);
            if (emulator.is32Bit()) {
                backend.reg_write(ArmConst.UC_ARM_REG_R0, -1);
            } else {
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, -1);
            }
        }
    }

}
