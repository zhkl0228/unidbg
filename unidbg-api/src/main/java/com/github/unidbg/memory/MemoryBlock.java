package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public interface MemoryBlock {

    UnidbgPointer getPointer();

    boolean isSame(Pointer pointer);

    void free();

}
