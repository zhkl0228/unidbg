package com.github.unidbg.linux.android.dvm.array;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.Array;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

abstract class BaseArray<T> extends DvmObject<T> implements Array<T> {

    BaseArray(T value) {
        super(null, value);
    }

    private MemoryBlock memoryBlock;

    @Override
    public UnicornPointer allocateMemoryBlock(Emulator<?> emulator, int length) {
        if (memoryBlock != null) {
            throw new IllegalStateException("Already allocated array memory");
        }

        memoryBlock = emulator.getMemory().malloc(length);
        return memoryBlock.getPointer();
    }

    @Override
    public void freeMemoryBlock(Pointer pointer) {
        if (this.memoryBlock != null && this.memoryBlock.isSame(pointer)) {
            this.memoryBlock.free(true);
            this.memoryBlock = null;
        }
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }

}
