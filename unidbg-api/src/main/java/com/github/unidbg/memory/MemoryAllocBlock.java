package com.github.unidbg.memory;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class MemoryAllocBlock implements MemoryBlock {

    public static MemoryBlock malloc(Emulator<?> emulator, Symbol malloc, Symbol free, int length) {
        Number number = malloc.call(emulator, length)[0];
        long address = emulator.is64Bit() ? number.longValue() : number.intValue() & 0xffffffffL;
        final UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
        return new MemoryAllocBlock(pointer, emulator, free);
    }

    private final UnidbgPointer pointer;
    private final Emulator<?> emulator;
    private final Symbol free;

    private MemoryAllocBlock(UnidbgPointer pointer, Emulator<?> emulator, Symbol free) {
        this.pointer = pointer;
        this.emulator = emulator;
        this.free = free;
    }

    @Override
    public UnidbgPointer getPointer() {
        return pointer;
    }

    @Override
    public boolean isSame(Pointer p) {
        return pointer.equals(p);
    }

    @Override
    public void free() {
        if (free == null) {
            throw new UnsupportedOperationException();
        }

        free.call(emulator, pointer);
    }
    
}
