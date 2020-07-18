package com.github.unidbg.hook;

import com.github.unidbg.Emulator;

public interface HookCallback {

    int onHook(Emulator<?> emulator);

}
