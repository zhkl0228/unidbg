package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public interface SignalTask extends Disposable {

    void runHandler(AbstractEmulator<?> emulator);

}
