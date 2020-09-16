package com.github.unidbg.memory;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public class MemoryAllocBlock implements MemoryBlock {

    public static MemoryBlock malloc(Emulator<?> emulator, Symbol malloc, Symbol free, int length) {
        Number number = malloc.call(emulator, length)[0];
        long address = emulator.is64Bit() ? number.longValue() : number.intValue() & 0xffffffffL;
        final UnicornPointer pointer = UnicornPointer.pointer(emulator, address);
        return new MemoryAllocBlock(pointer, emulator, free);
    }

    private final UnicornPointer pointer;
    private final Emulator<?> emulator;
    private final Symbol free;

    private MemoryAllocBlock(UnicornPointer pointer, Emulator<?> emulator, Symbol free) {
        this.pointer = pointer;
        this.emulator = emulator;
        this.free = free;
    }

    @Override
    public UnicornPointer getPointer() {
        return pointer;
    }

    @Override
    public boolean isSame(Pointer p) {
        return pointer.equals(p);
    }

    @Override
    public void free(boolean runtime) {
        if (runtime || free == null) {
            throw new UnsupportedOperationException();
        }

        free.call(emulator, pointer);
    }
    
}
