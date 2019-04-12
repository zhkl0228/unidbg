package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.pointer.UnicornPointer;

public interface RegisterContext {

    long getLr();

    UnicornPointer getLrPointer();

    /**
     * SP
     */
    UnicornPointer getStackPointer();

    void set(String key, Object value);
    <T> T get(String key);

}
