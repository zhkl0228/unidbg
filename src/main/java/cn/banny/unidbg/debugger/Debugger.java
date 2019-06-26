package cn.banny.unidbg.debugger;

import cn.banny.unidbg.Module;
import com.sun.jna.Pointer;
import unicorn.CodeHook;

import java.io.Closeable;

public interface Debugger extends CodeHook, Closeable {

    void addBreakPoint(Module module, String symbol);
    void addBreakPoint(Module module, long offset);

    /**
     * @param address 奇数地址表示thumb断点
     */
    void addBreakPoint(long address);

    void debug();

    void brk(Pointer pc, int svcNumber);

    void setDebugListener(DebugListener listener);

}
