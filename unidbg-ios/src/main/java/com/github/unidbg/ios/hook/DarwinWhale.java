package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.whale.IWhale;
import com.github.unidbg.hook.whale.Whale;

public class DarwinWhale extends Whale {

    public static IWhale getInstance(Emulator<?> emulator) {
        IWhale whale = emulator.get(Whale.class.getName());
        if (whale == null) {
            whale = new DarwinWhale(emulator);
            emulator.set(Whale.class.getName(), whale);
        }
        return whale;
    }

    private DarwinWhale(Emulator<?> emulator) {
        super(emulator, true);
    }

}
