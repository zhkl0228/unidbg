package com.github.unidbg.linux.thread;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class PThreadInternal extends UnidbgStructure {

    public static PThreadInternal create(Emulator<?> emulator, Pointer pointer) {
        return emulator.is64Bit() ? new PThreadInternal64(pointer) : new PThreadInternal32(pointer);
    }

    public int tid;

    public PThreadInternal(Pointer p) {
        super(p);
    }

}
