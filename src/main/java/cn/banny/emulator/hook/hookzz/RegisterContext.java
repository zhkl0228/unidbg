package cn.banny.emulator.hook.hookzz;

import com.sun.jna.Pointer;

public interface RegisterContext {

    long getLr();

    Pointer getLrPointer();

}
