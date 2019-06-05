package cn.banny.unidbg.debugger;

import cn.banny.unidbg.Module;
import com.sun.jna.Pointer;
import unicorn.CodeHook;

public interface Debugger extends CodeHook {

    void addBreakPoint(Module module, String symbol);
    void addBreakPoint(Module module, long offset);

    void debug();

    void brk(Pointer pc, int svcNumber);

    void setDebugListener(DebugListener listener);

}
