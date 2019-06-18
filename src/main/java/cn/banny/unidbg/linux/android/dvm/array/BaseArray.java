package cn.banny.unidbg.linux.android.dvm.array;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.linux.android.dvm.Array;
import cn.banny.unidbg.linux.android.dvm.DvmObject;
import cn.banny.unidbg.memory.MemoryBlock;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

abstract class BaseArray<T> extends DvmObject<T> implements Array<T> {

    BaseArray(T value) {
        super(null, value);
    }

    private MemoryBlock memoryBlock;

    @Override
    public UnicornPointer allocateMemoryBlock(Emulator emulator, int length) {
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

}
