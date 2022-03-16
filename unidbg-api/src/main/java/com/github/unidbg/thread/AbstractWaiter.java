package com.github.unidbg.thread;

import com.github.unidbg.signal.SignalTask;

public abstract class AbstractWaiter implements Waiter {

    @Override
    public void onSignal(SignalTask task) {
    }

}
