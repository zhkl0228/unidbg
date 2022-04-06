package com.github.unidbg.signal;

import com.github.unidbg.thread.BaseTask;

public abstract class AbstractSignalTask extends BaseTask implements com.github.unidbg.signal.SignalTask {

    protected final int signum;

    public AbstractSignalTask(int signum) {
        this.signum = signum;
    }

}
