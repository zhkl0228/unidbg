package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.dynarmic.DynarmicLoader;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    static {
        DynarmicLoader.useDynarmic();
    }

    public static void main(String[] args) throws IOException {
        Emulator<?> emulator = new DarwinARM64Emulator();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        emulator.getSyscallHandler().setVerbose(true);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_osx"));
        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
