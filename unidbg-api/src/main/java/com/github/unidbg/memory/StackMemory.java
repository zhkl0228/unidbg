package com.github.unidbg.memory;

import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.serialize.Serializable;

public interface StackMemory extends Serializable {

    UnidbgPointer writeStackString(String str);
    UnidbgPointer writeStackBytes(byte[] data);

}
