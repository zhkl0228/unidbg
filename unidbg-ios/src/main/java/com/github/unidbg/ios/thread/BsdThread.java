package com.github.unidbg.ios.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.ThreadTask;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class BsdThread extends ThreadTask {

    private final UnidbgPointer thread;
    private final UnidbgPointer fun;
    private final UnidbgPointer arg;

    private final UnidbgPointer stack;
    private final int stackSize;

    public BsdThread(Emulator<?> emulator, int tid, UnidbgPointer thread, UnidbgPointer fun, UnidbgPointer arg, int stackSize) {
        super(tid, emulator.getReturnAddress());
        this.thread = thread;
        this.fun = fun;
        this.arg = arg;
        this.stack = thread;
        this.stackSize = stackSize;
    }

    @Override
    protected Number runThread(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Symbol _pthread_start = emulator.getMemory().findModule("libsystem_pthread.dylib").findSymbolByName("__pthread_start", false);
        if (_pthread_start == null) {
            throw new IllegalStateException();
        }

        int pflags = 0;

        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_R0, this.thread.peer);
            backend.reg_write(ArmConst.UC_ARM_REG_R1, getId());
            backend.reg_write(ArmConst.UC_ARM_REG_R2, this.fun.peer);
            backend.reg_write(ArmConst.UC_ARM_REG_R3, this.arg == null ? 0 : this.arg.peer);

            stack.share(-8).setInt(0, stackSize);
            stack.share(-4).setInt(0, pflags);
            backend.reg_write(ArmConst.UC_ARM_REG_SP, stack.peer - 8);

            backend.reg_write(ArmConst.UC_ARM_REG_LR, until);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, this.thread.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X1, getId());
            backend.reg_write(Arm64Const.UC_ARM64_REG_X2, this.fun.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X3, this.arg == null ? 0 : this.arg.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X4, stackSize);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X5, pflags);

            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, stack.peer);

            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, until);
        }

        return emulator.emulate(_pthread_start.getAddress(), until);
    }

    @Override
    public boolean setErrno(Emulator<?> emulator, int errno) {
        Pthread pthread = Pthread.create(emulator, thread);
        if (pthread.errno != null) {
            pthread.errno.setInt(0, errno);
            return true;
        }
        return super.setErrno(emulator, errno);
    }

    @Override
    public String toString() {
        return "BsdThread fun=" + fun + ", arg=" + arg + ", stack=" + stack;
    }
}
