package cn.banny.unidbg.arm.context;

import cn.banny.unidbg.pointer.UnicornPointer;

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

    /**
     * sp
     */
    UnicornPointer getStackPointer();

}
