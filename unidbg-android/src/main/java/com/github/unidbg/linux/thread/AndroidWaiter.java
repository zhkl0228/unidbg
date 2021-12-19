package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.thread.Waiter;

public abstract class AndroidWaiter implements Waiter {

    @Override
    public void onContinueRun(Emulator<?> emulator) {
    }

}
