package cn.banny.emulator.memory;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public class MemoryAllocBlock implements MemoryBlock {

    public static MemoryBlock malloc(Emulator emulator, Symbol malloc, int length) {
        long address = malloc.call(emulator, length)[0].intValue() & 0xffffffffL;
        final UnicornPointer pointer = UnicornPointer.pointer(emulator, address);
        return new MemoryAllocBlock(pointer);
    }

    private final UnicornPointer pointer;

    private MemoryAllocBlock(UnicornPointer pointer) {
        this.pointer = pointer;
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
    public void free() {
        throw new UnsupportedOperationException();
    }
    
}
