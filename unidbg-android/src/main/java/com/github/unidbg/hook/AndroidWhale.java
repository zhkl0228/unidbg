package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.whale.IWhale;
import com.github.unidbg.hook.whale.Whale;

public class AndroidWhale extends Whale {

    public static IWhale getInstance(Emulator<?> emulator) {
        IWhale whale = emulator.get(Whale.class.getName());
        if (whale == null) {
            whale = new AndroidWhale(emulator);
            emulator.set(Whale.class.getName(), whale);
        }
        return whale;
    }

    private AndroidWhale(Emulator<?> emulator) {
        super(emulator, false);
    }

}
