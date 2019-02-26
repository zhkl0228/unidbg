package cn.banny.emulator.debugger;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.arm.CodeHistory;

public interface DebugListener {

    boolean canDebug(Emulator emulator, CodeHistory currentCode);

}
