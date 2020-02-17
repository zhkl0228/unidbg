package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnicornPointer;

public interface StackMemory {

    UnicornPointer writeStackString(String str);
    UnicornPointer writeStackBytes(byte[] data);

}
