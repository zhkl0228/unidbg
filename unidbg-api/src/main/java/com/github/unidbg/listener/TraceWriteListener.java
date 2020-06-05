package com.github.unidbg.listener;

import com.github.unidbg.Emulator;

public interface TraceWriteListener {

    void onWrite(Emulator<?> emulator, long address, int size, long value);

}
