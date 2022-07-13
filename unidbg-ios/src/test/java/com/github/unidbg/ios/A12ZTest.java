package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    public static void main(String[] args) throws IOException {
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
        builder.addBackendFactory(new HypervisorFactory(true));
        Emulator<?> emulator = builder.build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver().setOverride());
        emulator.getSyscallHandler().setVerbose(false);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_osx"));
        long start = System.currentTimeMillis();
        emulator.traceRead(0xfbffffda0L, 0xfbffffda0L + 0x8);
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
