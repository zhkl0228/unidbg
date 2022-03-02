package com.github.unidbg.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.signal.SignalTask;

public interface Waiter {

    boolean canDispatch();

    void onContinueRun(Emulator<?> emulator);

    void onSignal(SignalTask task);
}
