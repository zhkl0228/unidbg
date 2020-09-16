package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.MachOModule;

import java.io.File;

public interface EmulatorConfigurator {

    void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier);

    void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable);

}
