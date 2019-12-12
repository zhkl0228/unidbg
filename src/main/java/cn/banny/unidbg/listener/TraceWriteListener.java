package cn.banny.unidbg.listener;

import cn.banny.unidbg.Emulator;

public interface TraceWriteListener {

    void onWrite(Emulator emulator, long address, int size, long value);

}
