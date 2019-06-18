package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public interface Array<T> {

    int length();

    void setData(int start, T data);

    UnicornPointer allocateMemoryBlock(Emulator emulator, int length);
    void freeMemoryBlock(Pointer pointer);

}
