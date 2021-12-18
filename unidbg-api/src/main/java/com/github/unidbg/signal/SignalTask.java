package com.github.unidbg.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.thread.Disposable;
import com.github.unidbg.thread.Task;

public interface SignalTask extends Disposable {

    int getSigNumber();

    void runHandler(Task task, AbstractEmulator<?> emulator);

}
