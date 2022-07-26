package com.github.unidbg.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.FunctionCall;

public interface RunnableTask {

    boolean canDispatch();

    void saveContext(Emulator<?> emulator);

    boolean isContextSaved();

    void restoreContext(Emulator<?> emulator);

    void destroy(Emulator<?> emulator);

    void setWaiter(Emulator<?> emulator, Waiter waiter);

    Waiter getWaiter();

    void setResult(Emulator<?> emulator, Number ret);

    void setDestroyListener(DestroyListener listener);

    void popContext(Emulator<?> emulator);

    void pushFunction(Emulator<?> emulator, FunctionCall call);
    FunctionCall popFunction(Emulator<?> emulator, long address);

}
