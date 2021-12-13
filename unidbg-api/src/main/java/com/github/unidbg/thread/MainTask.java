package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public abstract class MainTask extends AbstractTask implements Task {

    protected final long begin;
    protected final long until;

    protected MainTask(long begin, long until) {
        this.begin = begin;
        this.until = until;
    }

    @Override
    public Number dispatch(AbstractEmulator<?> emulator) {
        if (isContextSaved()) {
            return continueRun(emulator, until);
        }
        return run(emulator);
    }

    protected abstract Number run(AbstractEmulator<?> emulator);

    @Override
    public boolean isMainThread() {
        return true;
    }

    @Override
    public String toString() {
        return "MainThread begin=0x" + Long.toHexString(begin) + ", until=" + Long.toHexString(until);
    }

}
