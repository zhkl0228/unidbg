package com.github.unidbg.linux.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.ThreadTask;
import unicorn.ArmConst;

public class KitKatThread extends ThreadTask {

    private final long __thread_entry;
    private final UnidbgPointer child_stack;
    private final UnidbgPointer fn;
    private final UnidbgPointer arg;

    public KitKatThread(long until, long __thread_entry, UnidbgPointer child_stack, UnidbgPointer fn, UnidbgPointer arg) {
        super(until);
        this.__thread_entry = __thread_entry;
        this.child_stack = child_stack;
        this.fn = fn;
        this.arg = arg;

        if (__thread_entry == 0) {
            throw new IllegalStateException();
        }
    }

    @Override
    public String toString() {
        return "KitKatThread fn=" + fn + ", arg=" + arg + ", child_stack=" + child_stack;
    }

    @Override
    protected Number runThread(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        UnidbgPointer stack = allocateStack(emulator);
        backend.reg_write(ArmConst.UC_ARM_REG_SP, stack.peer);

        backend.reg_write(ArmConst.UC_ARM_REG_R0, this.fn.peer);
        backend.reg_write(ArmConst.UC_ARM_REG_R1, this.arg == null ? 0 : this.arg.peer);
        backend.reg_write(ArmConst.UC_ARM_REG_R2, this.child_stack.peer);
        backend.reg_write(ArmConst.UC_ARM_REG_LR, until);
        return emulator.emulate(__thread_entry, until);
    }

}
