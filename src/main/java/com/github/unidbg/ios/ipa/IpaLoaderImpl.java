package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;

class IpaLoaderImpl extends IpaLoader {

    private final Emulator<DarwinFileIO> emulator;
    private final Module executable;

    IpaLoaderImpl(Emulator<DarwinFileIO> emulator, Module executable) {
        this.emulator = emulator;
        this.executable = executable;
    }

    @Override
    public void callEntry() {
        executable.callEntry(emulator);
    }

    @Override
    public Module getExecutable() {
        return executable;
    }

    @Override
    public Emulator<DarwinFileIO> getEmulator() {
        return emulator;
    }
}
