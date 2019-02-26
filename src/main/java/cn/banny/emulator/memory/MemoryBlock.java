package cn.banny.emulator.memory;

import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public interface MemoryBlock {

    UnicornPointer getPointer();

    boolean isSame(Pointer pointer);

    void free();

}
