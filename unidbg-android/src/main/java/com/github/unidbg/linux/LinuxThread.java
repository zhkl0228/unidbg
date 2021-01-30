package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.Thread;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class LinuxThread extends Thread {

    private static final Log log = LogFactory.getLog(LinuxThread.class);

    // Our 'tls' and __pthread_clone's 'child_stack' are one and the same, just growing in
    // opposite directions.
    private final Pointer child_stack;
    private final UnidbgPointer fn;
    private final Pointer arg;

    LinuxThread(Pointer child_stack, Pointer fn, Pointer arg) {
        this.child_stack = child_stack;
        this.fn = (UnidbgPointer) fn;
        this.arg = arg;
    }

    private long context;

    @Override
    public void runThread(Emulator<?> emulator, long __thread_entry) {
        Backend backend = emulator.getBackend();
        if (this.context == 0) {
            log.info("run thread: fn=" + this.fn + ", arg=" + this.arg + ", child_stack=" + this.child_stack);
            if (__thread_entry == 0) {
                Module.emulateFunction(emulator, this.fn.peer, this.arg);
            } else {
                Module.emulateFunction(emulator, __thread_entry, this.fn, this.arg, this.child_stack);
            }
        } else {
            backend.context_restore(this.context);
            long pc = backend.reg_read(emulator.is32Bit() ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC).intValue() & 0xffffffffL;
            log.info("resume thread: fn=" + this.fn + ", arg=" + this.arg + ", child_stack=" + this.child_stack + ", pc=0x" + Long.toHexString(pc));
            backend.emu_start(pc, 0, 0, 0);
        }
        if (this.context == 0) {
            this.context = backend.context_alloc();
        }
        backend.context_save(this.context);
    }

}
