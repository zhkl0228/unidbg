package com.github.unidbg.debugger;

import com.github.unidbg.Module;
import com.sun.jna.Pointer;
import unicorn.DebugHook;

import java.io.Closeable;

public interface Debugger extends DebugHook, Closeable {

    BreakPoint addBreakPoint(Module module, String symbol);
    BreakPoint addBreakPoint(Module module, String symbol, BreakPointCallback callback);
    BreakPoint addBreakPoint(Module module, long offset);
    BreakPoint addBreakPoint(Module module, long offset, BreakPointCallback callback);

    /**
     * @param address 奇数地址表示thumb断点
     */
    BreakPoint addBreakPoint(long address);
    BreakPoint addBreakPoint(long address, BreakPointCallback callback);

    void debug();

    void brk(Pointer pc, int svcNumber);

    @SuppressWarnings("unused")
    void setDebugListener(DebugListener listener);

}
