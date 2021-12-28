package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;

public interface RunnableTask {

    boolean canDispatch();

    void saveContext(Emulator<?> emulator);

    boolean isContextSaved();

    void restoreContext(Emulator<?> emulator);

    void destroy(Emulator<?> emulator);

    void setWaiter(Waiter waiter);

    Waiter getWaiter();

    void setResult(Emulator<?> emulator, Number ret);

    void setDestroyListener(DestroyListener listener);

    void popContext(Emulator<?> emulator);
}
