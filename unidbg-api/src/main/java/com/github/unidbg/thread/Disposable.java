package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public interface Disposable {

    void destroy(AbstractEmulator<?> emulator);

}
