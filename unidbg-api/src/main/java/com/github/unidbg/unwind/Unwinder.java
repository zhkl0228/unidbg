package com.github.unidbg.unwind;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.AbstractARMDebugger;

public interface Unwinder {

    void unwind(Emulator<?> emulator, AbstractARMDebugger debugger, boolean thumb);

}
