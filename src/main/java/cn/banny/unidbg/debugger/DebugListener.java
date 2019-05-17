package cn.banny.unidbg.debugger;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.CodeHistory;

public interface DebugListener {

    boolean canDebug(Emulator emulator, CodeHistory currentCode);

}
