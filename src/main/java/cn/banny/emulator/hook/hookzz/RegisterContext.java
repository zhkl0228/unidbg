package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.ValuePair;
import cn.banny.emulator.pointer.UnicornPointer;

public interface RegisterContext extends ValuePair {

    long getLr();

    UnicornPointer getLrPointer();

    /**
     * SP
     */
    UnicornPointer getStackPointer();

}
