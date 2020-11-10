package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public interface MemoryBlockObject {

    UnidbgPointer allocateMemoryBlock(Emulator<?> emulator, int length);
    void freeMemoryBlock(Pointer pointer);

}
