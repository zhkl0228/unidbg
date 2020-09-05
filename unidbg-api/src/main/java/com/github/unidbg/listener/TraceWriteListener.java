package com.github.unidbg.listener;

import com.github.unidbg.Emulator;

public interface TraceWriteListener {

    /**
     * @return 返回<code>true</code>打印内存信息
     */
    boolean onWrite(Emulator<?> emulator, long address, int size, long value);

}
