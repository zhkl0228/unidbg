package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public abstract class ThreadTask extends AbstractTask implements Task {

    protected final long until;

    protected ThreadTask(int tid, long until) {
        super(tid);
        this.until = until;
    }

    @Override
    public final boolean isMainThread() {
        return false;
    }

    private boolean finished;

    @Override
    public boolean isFinish() {
        return finished;
    }

    protected int exitStatus;

    public void setExitStatus(int status) {
        this.exitStatus = status;
        this.finished = true;
    }

    @Override
    public final Number dispatch(AbstractEmulator<?> emulator) throws PopContextException {
        if (isContextSaved()) {
            return continueRun(emulator, until);
        }
        return runThread(emulator);
    }

    protected abstract Number runThread(AbstractEmulator<?> emulator);

}
