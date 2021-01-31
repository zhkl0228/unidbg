package com.github.unidbg.ios;

import com.github.unidbg.EmulatorBuilder;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.file.ios.DarwinFileIO;

public class DarwinEmulatorBuilder extends EmulatorBuilder<ARMEmulator<DarwinFileIO>> {

    public static DarwinEmulatorBuilder builder32() {
        return new DarwinEmulatorBuilder(false);
    }

    public static DarwinEmulatorBuilder builder64() {
        return new DarwinEmulatorBuilder(true);
    }

    protected DarwinEmulatorBuilder(boolean is64Bit) {
        super(is64Bit);
    }

    @Override
    public ARMEmulator<DarwinFileIO> build() {
        return is64Bit ? new DarwinARM64Emulator(processName, rootDir, backendFactories) : new DarwinARMEmulator(processName, rootDir, backendFactories);
    }

}
