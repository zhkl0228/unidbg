package com.github.unidbg.linux.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.ThreadTask;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class SignalTask extends ThreadTask {

    private final UnidbgPointer stack;
    private final int signum;
    private final SigAction action;

    public SignalTask(Emulator<?> emulator, int signum, SigAction action) {
        super(emulator.getReturnAddress());
        this.stack = allocateStack(emulator);
        this.signum = signum;
        this.action = action;
    }

    @Override
    public String toString() {
        return "SignalTask sa_handler=" + action.sa_handler + ", stack=" + stack + ", signum=" + signum;
    }

    @Override
    protected Number runThread(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, stack.peer);
            backend.reg_write(ArmConst.UC_ARM_REG_R0, signum);
            backend.reg_write(ArmConst.UC_ARM_REG_R1, 0); // siginfo_t *info
            backend.reg_write(ArmConst.UC_ARM_REG_R2, 0); // void *ucontext
            backend.reg_write(ArmConst.UC_ARM_REG_LR, until);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, stack.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, signum);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X1, 0); // siginfo_t *info
            backend.reg_write(Arm64Const.UC_ARM64_REG_X2, 0); // void *ucontext
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, until);
        }
        UnidbgPointer handler = (UnidbgPointer) action.sa_handler;
        return emulator.emulate(handler.peer, until);
    }

}
