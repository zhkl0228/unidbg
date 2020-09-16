package com.github.unidbg.listener;

import com.github.unidbg.Emulator;

public interface TraceReadListener {

    /**
     * @return 返回<code>true</code>打印内存信息
     */
    boolean onRead(Emulator<?> emulator, long address, byte[] data, String hex);

}
