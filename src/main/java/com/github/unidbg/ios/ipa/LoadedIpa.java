package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;

public class LoadedIpa {

    private final Emulator<DarwinFileIO> emulator;
    private final Module executable;

    LoadedIpa(Emulator<DarwinFileIO> emulator, Module executable) {
        this.emulator = emulator;
        this.executable = executable;
    }

    public void callEntry(boolean call_didFinishLaunchingWithOptions) {
        if (call_didFinishLaunchingWithOptions) {
            executable.callEntry(emulator, "call", "didFinishLaunchingWithOptions");
        } else {
            executable.callEntry(emulator);
        }
    }

    public void callEntry() {
        callEntry(false);
    }

    public Module getExecutable() {
        return executable;
    }

    public Emulator<DarwinFileIO> getEmulator() {
        return emulator;
    }

}
