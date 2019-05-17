package cn.banny.unidbg.debugger;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import unicorn.CodeHook;

public interface Debugger extends CodeHook {

    void addBreakPoint(Module module, String symbol);
    void addBreakPoint(Module module, long offset);

    void debug(Emulator emulator);

    void setDebugListener(DebugListener listener);

}
