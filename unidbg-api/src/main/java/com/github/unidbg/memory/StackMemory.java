package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.serialize.Serializable;

public interface StackMemory extends Serializable {

    UnicornPointer writeStackString(String str);
    UnicornPointer writeStackBytes(byte[] data);

}
