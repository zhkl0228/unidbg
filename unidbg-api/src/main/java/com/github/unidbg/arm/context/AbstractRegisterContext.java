package com.github.unidbg.arm.context;

import com.github.unidbg.pointer.UnidbgPointer;

public abstract class AbstractRegisterContext implements RegisterContext {

    @Override
    public final int getIntArg(int index) {
        return (int) getLongArg(index);
    }

    @Override
    public final long getLongArg(int index) {
        UnidbgPointer pointer = getPointerArg(index);
        return pointer == null ? 0 : pointer.peer;
    }

}
