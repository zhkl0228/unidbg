package com.github.unidbg.debugger.ida;

import com.github.unidbg.Emulator;

public abstract class DebuggerEvent {

    public abstract byte[] pack(Emulator<?> emulator);

}
