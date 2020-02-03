package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.HookStatus;

public interface ReplaceCallback {

    HookStatus onCall(Emulator emulator, long originFunction);

}
