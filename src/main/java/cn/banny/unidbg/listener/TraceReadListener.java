package cn.banny.unidbg.listener;

import cn.banny.unidbg.Emulator;

public interface TraceReadListener {

    void onRead(Emulator emulator, long address, byte[] data, String hex);

}
