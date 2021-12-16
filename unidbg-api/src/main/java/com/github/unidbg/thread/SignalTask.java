package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public interface SignalTask {

    void runHandler(AbstractEmulator<?> emulator);

    void destroy(AbstractEmulator<?> emulator);

}
