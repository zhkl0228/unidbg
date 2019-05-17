package cn.banny.unidbg.memory;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public class MemoryAllocBlock implements MemoryBlock {

    public static MemoryBlock malloc(Emulator emulator, Symbol malloc, Symbol free, int length) {
        long address = malloc.call(emulator, length)[0].intValue() & 0xffffffffL;
        final UnicornPointer pointer = UnicornPointer.pointer(emulator, address);
        return new MemoryAllocBlock(pointer, emulator, free);
    }

    private final UnicornPointer pointer;
    private final Emulator emulator;
    private final Symbol free;

    private MemoryAllocBlock(UnicornPointer pointer, Emulator emulator, Symbol free) {
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
