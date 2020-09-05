package com.github.unidbg.pointer;

public interface MemoryWriteListener {

    void onSystemWrite(long addr, byte[] data);

}
