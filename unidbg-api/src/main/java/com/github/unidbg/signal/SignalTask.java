package com.github.unidbg.signal;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.thread.Disposable;

public interface SignalTask extends Disposable {

    int getSigNumber();

    void runHandler(AbstractEmulator<?> emulator);

}
