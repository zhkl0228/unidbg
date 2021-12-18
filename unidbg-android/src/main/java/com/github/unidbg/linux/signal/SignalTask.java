package com.github.unidbg.linux.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.thread.BaseTask;
import com.github.unidbg.thread.Task;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class SignalTask extends BaseTask implements com.github.unidbg.signal.SignalTask {

    private final int signum;
    private final SigAction action;

    public SignalTask(int signum, SigAction action) {
        this.signum = signum;
        this.action = action;
    }

    @Override
    public int getSigNumber() {
        return signum;
    }

    private UnidbgPointer stack;

    @Override
    public void runHandler(Task task, AbstractEmulator<?> emulator) {
        SigSet sigSet = task.getSigMaskSet();
        try {
            long sa_mask = action.getMask();
            if (sigSet == null) {
                task.setSigMaskSet(new com.github.unidbg.linux.signal.SigSet(sa_mask));
            } else {
                sigSet.blockSigSet(sa_mask);
            }
            Backend backend = emulator.getBackend();
            if (stack == null) {
                stack = allocateStack(emulator);
            }
            if (action.needSigInfo() && infoBlock == null) {
                infoBlock = emulator.getMemory().malloc(128, true);
                infoBlock.getPointer().setInt(0, signum);
            }
            if (emulator.is32Bit()) {
                backend.reg_write(ArmConst.UC_ARM_REG_SP, stack.peer);
                backend.reg_write(ArmConst.UC_ARM_REG_R0, signum);
                backend.reg_write(ArmConst.UC_ARM_REG_R1, infoBlock == null ? 0 : infoBlock.getPointer().peer); // siginfo_t *info
                backend.reg_write(ArmConst.UC_ARM_REG_R2, 0); // void *ucontext
                backend.reg_write(ArmConst.UC_ARM_REG_LR, emulator.getReturnAddress());
            } else {
                backend.reg_write(Arm64Const.UC_ARM64_REG_SP, stack.peer);
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, signum);
                backend.reg_write(Arm64Const.UC_ARM64_REG_X1, infoBlock == null ? 0 : infoBlock.getPointer().peer); // siginfo_t *info
                backend.reg_write(Arm64Const.UC_ARM64_REG_X2, 0); // void *ucontext
                backend.reg_write(Arm64Const.UC_ARM64_REG_LR, emulator.getReturnAddress());
            }
            Number ret = emulator.emulate(UnidbgPointer.nativeValue(action.sa_handler), emulator.getReturnAddress());
            if (ret == null) {
                throw new IllegalStateException();
            }
        } finally {
            task.setSigMaskSet(sigSet);
        }
    }

    @Override
    public String toString() {
        return "SignalTask sa_handler=" + action.sa_handler + ", stack=" + stack + ", signum=" + signum;
    }

    private MemoryBlock infoBlock;

    @Override
    public void destroy(AbstractEmulator<?> emulator) {
        super.destroy(emulator);

        if (infoBlock != null) {
            infoBlock.free();
            infoBlock = null;
        }
    }

}
