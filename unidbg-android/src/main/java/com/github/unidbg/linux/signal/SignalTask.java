package com.github.unidbg.linux.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.signal.AbstractSignalTask;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.UnixSigSet;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class SignalTask extends AbstractSignalTask {

    private final SigAction action;
    private Pointer sig_info;

    public SignalTask(int signum, SigAction action) {
        this(signum, action, null);
    }

    public SignalTask(int signum, SigAction action, Pointer sig_info) {
        super(signum);
        this.action = action;
        this.sig_info = sig_info;
    }

    private UnidbgPointer stack;

    @Override
    public Number callHandler(SignalOps signalOps, AbstractEmulator<?> emulator) {
        SigSet sigSet = signalOps.getSigMaskSet();
        try {
            long sa_mask = action.getMask();
            if (sigSet == null) {
                SigSet newSigSet = new UnixSigSet(sa_mask);
                signalOps.setSigMaskSet(newSigSet);
            } else {
                sigSet.blockSigSet(sa_mask);
            }
            if (isContextSaved()) {
                return continueRun(emulator, emulator.getReturnAddress());
            }
            return runHandler(emulator);
        } finally {
            signalOps.setSigMaskSet(sigSet);
        }
    }

    private Number runHandler(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (stack == null) {
            stack = allocateStack(emulator);
        }
        if (action.needSigInfo() && infoBlock == null && sig_info == null) {
            infoBlock = emulator.getMemory().malloc(128, true);
            infoBlock.getPointer().setInt(0, signum);
            sig_info = infoBlock.getPointer();
        }
        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, stack.peer);
            backend.reg_write(ArmConst.UC_ARM_REG_R0, signum);
            backend.reg_write(ArmConst.UC_ARM_REG_R1, sig_info == null ? 0 : ((UnidbgPointer) sig_info).toIntPeer() /*infoBlock == null ? 0 : infoBlock.getPointer().peer*/); // siginfo_t *info
            backend.reg_write(ArmConst.UC_ARM_REG_R2, 0); // void *ucontext
            backend.reg_write(ArmConst.UC_ARM_REG_LR, emulator.getReturnAddress());
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, stack.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, signum);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X1, sig_info == null ? 0 : ((UnidbgPointer) sig_info).toUIntPeer()); // siginfo_t *info
            backend.reg_write(Arm64Const.UC_ARM64_REG_X2, 0); // void *ucontext
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, emulator.getReturnAddress());
        }
        long handler = UnidbgPointer.nativeValue(action.sa_handler);
        // 如果handler忽略或缺省，直接返回
        if (handler == 1 || handler == 0) {
            return -1;
        }
        return emulator.emulate(handler, emulator.getReturnAddress());
    }

    @Override
    public String toString() {
        return "SignalTask sa_handler=" + action.sa_handler + ", stack=" + stack + ", signum=" + signum;
    }

    private MemoryBlock infoBlock;

    @Override
    public void destroy(Emulator<?> emulator) {
        super.destroy(emulator);

        if (infoBlock != null) {
            infoBlock.free();
            infoBlock = null;
        }
    }

}
