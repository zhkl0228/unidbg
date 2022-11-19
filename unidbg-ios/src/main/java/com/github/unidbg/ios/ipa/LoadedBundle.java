package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.ios.DarwinFileIO;

public class LoadedBundle {

    private final Emulator<DarwinFileIO> emulator;
    private final Module bundle;
    private final String bundleIdentifier;
    private final String bundleVersion;

    LoadedBundle(Emulator<DarwinFileIO> emulator, Module bundle, String bundleIdentifier, String bundleVersion) {
        this.emulator = emulator;
        this.bundle = bundle;
        this.bundleIdentifier = bundleIdentifier;
        this.bundleVersion = bundleVersion;
    }

    public Emulator<DarwinFileIO> getEmulator() {
        return emulator;
    }

    public Module getBundle() {
        return bundle;
    }

    public String getBundleIdentifier() {
        return bundleIdentifier;
    }

    public String getBundleVersion() {
        return bundleVersion;
    }

}
