package com.github.unidbg.debugger;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.CodeHistory;

public interface DebugListener {

    boolean canDebug(Emulator<?> emulator, CodeHistory currentCode);

}
