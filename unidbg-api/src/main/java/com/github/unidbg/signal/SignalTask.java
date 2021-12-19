package com.github.unidbg.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.thread.RunnableTask;

public interface SignalTask extends RunnableTask {

    int getSigNumber();

    Number callHandler(SignalOps signalOps, AbstractEmulator<?> emulator);

}
