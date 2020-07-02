package com.github.unidbg.ios;

import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;

import java.io.File;

public class MountTest extends EmulatorTest<DarwinARM64Emulator> {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected DarwinARM64Emulator createARMEmulator() {
        return new DarwinARM64Emulator();
    }

    private void processMount() {
        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/mount"));

        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator);
        System.err.println("processMount ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    public static void main(String[] args) throws Exception {
        MountTest test = new MountTest();
        test.setUp();
        test.processMount();
        test.tearDown();
    }

}
