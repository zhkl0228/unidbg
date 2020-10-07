package com.github.unidbg.arm.context;

import com.github.unidbg.pointer.UnidbgPointer;

public interface RegisterContext {

    /**
     * @param index 0 based
     */
    int getIntArg(int index);

    /**
     * @param index 0 based
     */
    long getLongArg(int index);

    /**
     * @param index 0 based
     */
    UnidbgPointer getPointerArg(int index);

    long getLR();

    UnidbgPointer getLRPointer();

    UnidbgPointer getPCPointer();

    /**
     * sp
     */
    UnidbgPointer getStackPointer();

    int getInt(int regId);
    long getLong(int regId);

}
