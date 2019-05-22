package cn.banny.unidbg.arm;

import cn.banny.unidbg.pointer.UnicornPointer;

public interface RegisterContext {

    long getLr();

    UnicornPointer getLrPointer();

    /**
     * sp
     */
    UnicornPointer getStackPointer();

}
