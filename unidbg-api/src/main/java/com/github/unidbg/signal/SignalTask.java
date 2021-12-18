package com.github.unidbg.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.thread.Disposable;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadDispatcher;

public interface SignalTask extends Disposable {

    int getSigNumber();

    void runHandler(SignalOps signalOps, AbstractEmulator<?> emulator);

}
