package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.whale.IWhale;
import com.github.unidbg.hook.whale.Whale;
import com.github.unidbg.ios.URLibraryFile;
import com.github.unidbg.spi.LibraryFile;

import java.net.URL;
import java.util.Collections;

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

    @Override
    protected LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, null, Collections.<String>emptyList());
    }

}
