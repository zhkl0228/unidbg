package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.ios.URLibraryFile;
import com.github.unidbg.spi.LibraryFile;

import java.net.URL;
import java.util.Collections;

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

    @Override
    protected LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, null, Collections.<String>emptyList());
    }
}
