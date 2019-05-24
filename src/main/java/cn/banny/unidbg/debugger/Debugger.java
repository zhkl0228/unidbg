package cn.banny.unidbg.debugger;

import cn.banny.unidbg.Module;
import unicorn.CodeHook;

public interface Debugger extends CodeHook {

    void addBreakPoint(Module module, String symbol);
    void addBreakPoint(Module module, long offset);

    void debug();

    void setDebugListener(DebugListener listener);

}
