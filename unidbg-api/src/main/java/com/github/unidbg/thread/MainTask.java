package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public abstract class MainTask extends AbstractTask implements Task {

    protected final long until;

    protected MainTask(int pid, long until) {
        super(pid);
        this.until = until;
    }

    @Override
    public Number dispatch(AbstractEmulator<?> emulator) throws PopContextException {
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
    public boolean isFinish() {
        return false;
    }

}
