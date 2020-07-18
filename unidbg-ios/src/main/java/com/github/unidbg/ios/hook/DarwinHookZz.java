package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.hookzz.HookZz;

public class DarwinHookZz extends HookZz {

    public static HookZz getInstance(Emulator<?> emulator) {
        HookZz hookZz = emulator.get(HookZz.class.getName());
        if (hookZz == null) {
            hookZz = new DarwinHookZz(emulator);
            emulator.set(HookZz.class.getName(), hookZz);
        }
        return hookZz;
    }

    private DarwinHookZz(Emulator<?> emulator) {
        super(emulator, true);
    }
}
