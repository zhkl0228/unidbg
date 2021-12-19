package com.github.unidbg.thread;

import com.github.unidbg.Emulator;

public interface Waiter {

    boolean canDispatch();

    void onContinueRun(Emulator<?> emulator);

}
