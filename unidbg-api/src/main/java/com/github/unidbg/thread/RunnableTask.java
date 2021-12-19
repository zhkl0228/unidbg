package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;

public interface RunnableTask {

    boolean canDispatch();

    void saveContext(AbstractEmulator<?> emulator);

    boolean isContextSaved();

    void restoreContext(AbstractEmulator<?> emulator);

    void destroy(AbstractEmulator<?> emulator);

}
