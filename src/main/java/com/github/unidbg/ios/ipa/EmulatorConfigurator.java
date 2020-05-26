package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.ios.DarwinFileIO;

import java.io.File;

public interface EmulatorConfigurator {

    void configure(Emulator<DarwinFileIO> emulator, String processName, File rootDir);

}
