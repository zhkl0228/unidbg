package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.hookzz.Dobby;

public class AndroidDobby extends Dobby {

    public static Dobby getInstance(Emulator<?> emulator) {
        Dobby dobby = emulator.get(Dobby.class.getName());
        if (dobby == null) {
            dobby = new AndroidDobby(emulator);
            emulator.set(Dobby.class.getName(), dobby);
        }
        return dobby;
    }

    private AndroidDobby(Emulator<?> emulator) {
        super(emulator, false);
    }
}
