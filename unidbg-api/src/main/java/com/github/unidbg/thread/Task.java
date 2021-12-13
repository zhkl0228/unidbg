package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

interface Task {

    boolean canDispatch();

    Number dispatch(AbstractEmulator<?> emulator);

    void saveContext(AbstractEmulator<?> emulator);

    boolean isMainThread();

    void destroy(AbstractEmulator<?> emulator);

}
