package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.linux.android.URLibraryFile;
import com.github.unidbg.spi.LibraryFile;

import java.net.URL;

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

    @Override
    protected LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, -1);
    }
}
