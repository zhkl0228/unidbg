package com.github.unidbg;

import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public abstract class Symbol {

    private final String name;

    public Symbol(String name) {
        this.name = name;
    }

    public abstract Number[] call(Emulator<?> emulator, Object... args);

    public  abstract long getAddress();

    public abstract long getValue();

    public abstract boolean isUndef();

    private UnicornPointer namePointer;

    public final UnicornPointer createNameMemory(SvcMemory svcMemory) {
        if (namePointer == null) {
            byte[] name = getName().getBytes();
            namePointer = svcMemory.allocate(name.length + 1, "Symbol." + getName());
            namePointer.write(0, name, 0, name.length);
            namePointer.setByte(name.length, (byte) 0);
        }
        return namePointer;
    }

    public Pointer createPointer(Emulator<?> emulator) {
        return UnicornPointer.pointer(emulator, getAddress());
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
