package cn.banny.unidbg.memory;

import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public interface MemoryBlock {

    UnicornPointer getPointer();

    boolean isSame(Pointer pointer);

    void free(boolean runtime);

}
