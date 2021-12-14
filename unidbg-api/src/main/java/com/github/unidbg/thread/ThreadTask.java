package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public abstract class ThreadTask extends AbstractTask implements Task {

    protected final long until;

    protected ThreadTask(long until) {
        this.until = until;
    }

    @Override
    public final boolean isMainThread() {
        return false;
    }

    private int exitStatus;

    public void setExitStatus(int status) {
        this.exitStatus = status;
        setFinished();
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
