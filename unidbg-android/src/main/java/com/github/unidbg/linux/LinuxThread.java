package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.Thread;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class LinuxThread extends Thread {

    private static final Log log = LogFactory.getLog(LinuxThread.class);

    // Our 'tls' and __pthread_clone's 'child_stack' are one and the same, just growing in
    // opposite directions.
    private final UnidbgPointer child_stack;
    private final UnidbgPointer fn;
    private final UnidbgPointer arg;

    LinuxThread(UnidbgPointer child_stack, UnidbgPointer fn, UnidbgPointer arg) {
        this.child_stack = child_stack;
        this.fn = fn;
        this.arg = arg;
    }

    private long context;

    @Override
    public void runThread(Emulator<?> emulator, long __thread_entry, long timeout) {
        Backend backend = emulator.getBackend();
        if (this.context == 0) {
            log.info("run thread: fn=" + this.fn + ", arg=" + this.arg + ", child_stack=" + this.child_stack + ", __thread_entry=0x" + Long.toHexString(__thread_entry));
            if (__thread_entry == 0) {
                emulator.eThread(this.fn.peer, this.arg.peer, child_stack.peer);
            } else {
                Module.emulateFunction(emulator, __thread_entry, this.fn, this.arg, this.child_stack);
            }
        } else {
            backend.context_restore(this.context);
            long pc = backend.reg_read(emulator.is32Bit() ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC).longValue();
            if (emulator.is32Bit()) {
                pc &= 0xffffffffL;
            }
            log.info("resume thread: fn=" + this.fn + ", arg=" + this.arg + ", child_stack=" + this.child_stack + ", pc=0x" + Long.toHexString(pc) + ", __thread_entry=0x" + Long.toHexString(__thread_entry));
            backend.emu_start(pc, 0, timeout, 0);
        }
        if (this.context == 0) {
            this.context = backend.context_alloc();
        }
        backend.context_save(this.context);
    }

}
