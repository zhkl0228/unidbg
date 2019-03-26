package cn.banny.emulator.hook;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.arm.HookStatus;

public interface ReplaceCallback {

    HookStatus onCall(Emulator emulator, long originFunction);

}
