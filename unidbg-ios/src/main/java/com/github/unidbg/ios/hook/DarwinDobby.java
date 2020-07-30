package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.hookzz.Dobby;

public class DarwinDobby extends Dobby {

    public static Dobby getInstance(Emulator<?> emulator) {
        Dobby dobby = emulator.get(Dobby.class.getName());
        if (dobby == null) {
            dobby = new DarwinDobby(emulator);
            emulator.set(Dobby.class.getName(), dobby);
        }
        return dobby;
    }

    private DarwinDobby(Emulator<?> emulator) {
        super(emulator, true);
    }
}
