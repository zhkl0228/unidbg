package com.github.unidbg.linux.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.ThreadTask;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class MarshmallowThread extends ThreadTask {

    private final UnidbgPointer fn;
    private final UnidbgPointer thread;

    public MarshmallowThread(Emulator<?> emulator, UnidbgPointer fn, UnidbgPointer thread, Pointer tidptr, int tid) {
        super(tid, emulator.getReturnAddress());
        this.fn = fn;
        this.thread = thread;
        this.tidptr = tidptr;
    }

    @Override
    public void setExitStatus(int status) {
        super.setExitStatus(status);

        if (tidptr != null) {
            // set tid
            tidptr.setInt(0, 0);
        }
    }

    @Override
    public String toString() {
        return "MarshmallowThread fn=" + fn + ", arg=" + thread;
    }

    @Override
    protected Number runThread(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        UnidbgPointer stack = allocateStack(emulator);
        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_R0, UnidbgPointer.nativeValue(thread));
            backend.reg_write(ArmConst.UC_ARM_REG_SP, stack.peer);
            backend.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, UnidbgPointer.nativeValue(thread.share(0x48))); // tls
            backend.reg_write(ArmConst.UC_ARM_REG_LR, until);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, UnidbgPointer.nativeValue(thread));
            backend.reg_write(Arm64Const.UC_ARM64_REG_SP, stack.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, UnidbgPointer.nativeValue(thread.share(0xb0))); // tls
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, until);
        }
        return emulator.emulate(this.fn.peer, until);
    }

    private Pointer tidptr;

    public void set_tid_address(Pointer tidptr) {
        this.tidptr = tidptr;
    }

}
