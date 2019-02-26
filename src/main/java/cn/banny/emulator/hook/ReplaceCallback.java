package cn.banny.emulator.hook;

import cn.banny.emulator.arm.HookStatus;
import unicorn.Unicorn;

public interface ReplaceCallback {

    HookStatus onCall(Unicorn unicorn, long originFunction);

}
