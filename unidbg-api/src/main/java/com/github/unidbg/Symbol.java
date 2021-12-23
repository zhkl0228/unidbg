package com.github.unidbg;

import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public abstract class Symbol {

    private final String name;

    public Symbol(String name) {
        this.name = name;
    }

    public abstract Number call(Emulator<?> emulator, Object... args);

    public  abstract long getAddress();

    public abstract long getValue();

    public abstract boolean isUndef();

    public final UnidbgPointer createNameMemory(SvcMemory svcMemory) {
        return svcMemory.allocateSymbolName(name);
    }

    public Pointer createPointer(Emulator<?> emulator) {
        return UnidbgPointer.pointer(emulator, getAddress());
    }

    public String getName() {
        return name;
    }

    public abstract String getModuleName();

    @Override
    public String toString() {
        return name;
    }
}
