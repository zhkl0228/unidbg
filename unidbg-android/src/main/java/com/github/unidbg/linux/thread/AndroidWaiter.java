package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.thread.AbstractWaiter;
import com.github.unidbg.thread.Waiter;

public abstract class AndroidWaiter extends AbstractWaiter implements Waiter {

    @Override
    public void onContinueRun(Emulator<?> emulator) {
    }
}
