package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.hookzz.HookZz;

public class AndroidHookZz extends HookZz {

    public static HookZz getInstance(Emulator<?> emulator) {
        HookZz hookZz = emulator.get(HookZz.class.getName());
        if (hookZz == null) {
            hookZz = new AndroidHookZz(emulator);
            emulator.set(HookZz.class.getName(), hookZz);
        }
        return hookZz;
    }

    private AndroidHookZz(Emulator<?> emulator) {
        super(emulator, false);
    }
}
