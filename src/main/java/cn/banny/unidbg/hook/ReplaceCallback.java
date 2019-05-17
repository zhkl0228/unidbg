package cn.banny.unidbg.hook;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.HookStatus;

public interface ReplaceCallback {

    HookStatus onCall(Emulator emulator, long originFunction);

}
