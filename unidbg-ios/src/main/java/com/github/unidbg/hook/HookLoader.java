package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.URLibraryFile;
import com.github.unidbg.ios.hook.FishHook;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.spi.LibraryFile;

import java.net.URL;
import java.util.Collections;

public class HookLoader extends BaseHook {

    public static void load(Emulator<?> emulator) {
        Substrate.getInstance(emulator); // load substrate first
        FishHook.getInstance(emulator); // load fishhook

        HookLoader loader = emulator.get(HookLoader.class.getName());
        if (loader == null) {
            loader = new HookLoader(emulator);
            emulator.set(HookLoader.class.getName(), loader);
        }
    }

    private HookLoader(Emulator<?> emulator) {
        super(emulator, "libhook");
    }

    @Override
    protected LibraryFile createURLibraryFile(URL url, String libName) {
        return new URLibraryFile(url, libName, null, Collections.<String>emptyList());
    }

}
