package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

public abstract class BaseTask implements RunnableTask {

    private static final Log log = LogFactory.getLog(BaseTask.class);

    private Waiter waiter;

    @Override
    public void setWaiter(Waiter waiter) {
        this.waiter = waiter;
    }

    @Override
    public Waiter getWaiter() {
        return waiter;
    }

    @Override
    public final boolean canDispatch() {
        if (waiter != null) {
            return waiter.canDispatch();
        }
        return true;
    }

    private long context;

    @Override
    public final boolean isContextSaved() {
        return this.context != 0;
    }

    @Override
    public final void saveContext(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (this.context == 0) {
            this.context = backend.context_alloc();
        }
        backend.context_save(this.context);
    }

    @Override
    public void restoreContext(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        backend.context_restore(this.context);
    }

    protected final Number continueRun(AbstractEmulator<?> emulator, long until) {
        Backend backend = emulator.getBackend();
        backend.context_restore(this.context);
        long pc = backend.reg_read(emulator.is32Bit() ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC).longValue();
        if (emulator.is32Bit()) {
            pc &= 0xffffffffL;
            if (ARM.isThumb(backend)) {
                pc += 1;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("continue run task=" + this + ", pc=" + UnidbgPointer.pointer(emulator, pc) + ", until=0x" + Long.toHexString(until));
        }
        Waiter waiter = getWaiter();
        if (waiter != null) {
            waiter.onContinueRun(emulator);
            setWaiter(null);
        }
        return emulator.emulate(pc, until);
    }

    @Override
    public void destroy(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();

        if (stackBlock != null) {
            stackBlock.free();
            stackBlock = null;
        }

        if (this.context != 0) {
            backend.context_free(this.context);
            this.context = 0;
        }
    }

    public static final int THREAD_STACK_SIZE = 0x80000;

    private MemoryBlock stackBlock;

    protected final UnidbgPointer allocateStack(Emulator<?> emulator) {
        if (stackBlock == null) {
            stackBlock = emulator.getMemory().malloc(THREAD_STACK_SIZE, true);
        }
        return stackBlock.getPointer().share(THREAD_STACK_SIZE, 0);
    }

}
