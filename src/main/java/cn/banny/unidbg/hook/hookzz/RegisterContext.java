package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.spi.ValuePair;
import cn.banny.unidbg.pointer.UnicornPointer;

public interface RegisterContext extends ValuePair {

    long getLr();

    UnicornPointer getLrPointer();

    /**
     * SP
     */
    UnicornPointer getStackPointer();

}
