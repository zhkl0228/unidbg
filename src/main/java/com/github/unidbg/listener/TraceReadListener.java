package com.github.unidbg.listener;

import com.github.unidbg.Emulator;

public interface TraceReadListener {

    void onRead(Emulator<?> emulator, long address, byte[] data, String hex);

}
