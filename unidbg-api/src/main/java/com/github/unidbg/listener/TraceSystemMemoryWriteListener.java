package com.github.unidbg.listener;

import com.github.unidbg.Emulator;

public interface TraceSystemMemoryWriteListener {

    void onWrite(Emulator<?> emulator, long address, byte[] buf);

}
