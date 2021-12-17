package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalTask;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

abstract class AbstractTask extends BaseTask implements Task {

    private static final Log log = LogFactory.getLog(AbstractTask.class);

    private final int id;

    public AbstractTask(int id) {
        this.id = id;
    }

    private SigSet sigMaskSet;
    private SigSet sigPendingSet;

    @Override
    public SigSet getSigMaskSet() {
        return sigMaskSet;
    }

    @Override
    public SigSet getSigPendingSet() {
        return sigPendingSet;
    }

    @Override
    public void setSigMaskSet(SigSet sigMaskSet, SigSet sigPendingSet) {
        this.sigMaskSet = sigMaskSet;
        this.sigPendingSet = sigPendingSet;
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public final boolean canDispatch() {
        return true;
    }

    private long context;

    @Override
    public final boolean isContextSaved() {
        return this.context != 0;
    }

    private final List<SignalTask> signalTaskList = new ArrayList<>();

    @Override
    public void addSignalTask(SignalTask task) {
        signalTaskList.add(task);
    }

    @Override
    public void removeSignalTask(SignalTask task) {
        signalTaskList.remove(task);
    }

    @Override
    public List<SignalTask> getSignalTaskList() {
        return signalTaskList.isEmpty() ? Collections.<SignalTask>emptyList() : new ArrayList<>(signalTaskList);
    }

    @Override
    public void restoreContext(AbstractEmulator<?> emulator) {
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
    public void destroy(AbstractEmulator<?> emulator) {
        super.destroy(emulator);

        Backend backend = emulator.getBackend();
        if (this.context != 0) {
            backend.context_free(this.context);
            this.context = 0;
        }
    }

}
