package com.github.unidbg.arm.context;

import com.github.unidbg.pointer.UnicornPointer;

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
    UnicornPointer getPointerArg(int index);

    long getLR();

    UnicornPointer getLRPointer();

    UnicornPointer getPCPointer();

    /**
     * sp
     */
    UnicornPointer getStackPointer();

    int getInt(int regId);
    long getLong(int regId);

}
