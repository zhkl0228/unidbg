package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.backend.Backend;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

abstract class AbstractTask implements Task {

    private static final Log log = LogFactory.getLog(AbstractTask.class);

    @Override
    public final boolean canDispatch() {
        return true;
    }

    private long context;

    protected final boolean isContextSaved() {
        return this.context != 0;
    }

    protected final Number continueRun(AbstractEmulator<?> emulator, long until) {
        Backend backend = emulator.getBackend();
        backend.context_restore(this.context);
        long pc = backend.reg_read(emulator.is32Bit() ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC).longValue();
        if (emulator.is32Bit()) {
            pc &= 0xffffffffL;
        }
        if (log.isDebugEnabled()) {
            log.debug("resume task=" + this + ", pc=0x" + Long.toHexString(pc) + ", until=0x" + Long.toHexString(until));
        }
        return emulator.emulate(pc, until);
    }

    @Override
    public final void saveContext(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (this.context == 0) {
            this.context = backend.context_alloc();
        }
        backend.context_save(this.context);
    }

    @Override
    public final void destroy(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (this.context != 0) {
            backend.context_free(this.context);
            this.context = 0;
        }
    }
}
