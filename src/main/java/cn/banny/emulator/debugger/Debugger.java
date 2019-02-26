package cn.banny.emulator.debugger;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.Module;
import unicorn.CodeHook;

public interface Debugger extends CodeHook {

    void addBreakPoint(Module module, String symbol);
    void addBreakPoint(Module module, long offset);

    void debug(Emulator emulator);

    void setDebugListener(DebugListener listener);

}
