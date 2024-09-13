package com.github.unidbg.ios.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.ios.struct.kernel.Pthread;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.ThreadTask;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public class DarwinThread extends ThreadTask {

    private final UnidbgPointer start_routine;
    private final UnidbgPointer arg;
    private final Pthread pthread;
    private final int threadId;
    private final Pointer errno;

    public DarwinThread(Emulator<?> emulator, UnidbgPointer start_routine, UnidbgPointer arg, Pthread pthread, int threadId, Pointer errno) {
        super(emulator.getPid(), emulator.getReturnAddress());

        this.start_routine = start_routine;
        this.arg = arg;
        this.pthread = pthread;
        this.threadId = threadId;
        this.errno = errno;
    }

    @Override
    public void setResult(Emulator<?> emulator, Number ret) {
        super.setResult(emulator, ret);

        pthread.unpack();
        pthread.setExitValue(ret.intValue());
        pthread.pack();
    }

    public int getThreadId() {
        return threadId;
    }

    @Override
    public String toThreadString() {
        return "DarwinThread start_routine=" + start_routine + ", arg=" + arg;
    }

    @Override
    protected Number runThread(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();

        UnidbgPointer stack = allocateStack(emulator);
        pthread.setStack(stack, (long) THREAD_STACK_PAGE * emulator.getPageAlign());
        pthread.pack();

        backend.reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_R0 : Arm64Const.UC_ARM64_REG_X0, this.arg == null ? 0L : this.arg.peer);
        backend.reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_SP : Arm64Const.UC_ARM64_REG_SP, stack.peer);

        UnidbgPointer tsd = pthread.getTSD();
        tsd.setPointer(0, pthread.getPointer());
        tsd.setPointer(emulator.getPointerSize(), pthread.getErrno());
        pthread.getErrno().setPointer(0, errno);

        if (emulator.is32Bit()) {
            backend.reg_write(ArmConst.UC_ARM_REG_C13_C0_3, tsd.peer);
            backend.reg_write(ArmConst.UC_ARM_REG_LR, until);
        } else {
            backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDRRO_EL0, tsd.peer);
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, until);
        }

        return emulator.emulate(this.start_routine.peer, until);
    }

    @Override
    public boolean setErrno(Emulator<?> emulator, int errno) {
        this.errno.setInt(0, errno);
        return true;
    }

}
