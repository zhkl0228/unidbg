package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;

public abstract class ThreadTask extends AbstractTask implements Task {

    protected final long until;

    protected ThreadTask(long until) {
        this.until = until;
    }

    @Override
    public final boolean isMainThread() {
        return false;
    }

    @Override
    public final Number dispatch(AbstractEmulator<?> emulator) {
        if (isContextSaved()) {
            return continueRun(emulator, until);
        }
        return runThread(emulator);
    }

    protected abstract Number runThread(AbstractEmulator<?> emulator);

}
