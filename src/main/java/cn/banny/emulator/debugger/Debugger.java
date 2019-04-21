package cn.banny.emulator.debugger;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.LinuxModule;
import unicorn.CodeHook;

public interface Debugger extends CodeHook {

    void addBreakPoint(LinuxModule module, String symbol);
    void addBreakPoint(LinuxModule module, long offset);

    void debug(Emulator emulator);

    void setDebugListener(DebugListener listener);

}
