package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.backend.hypervisor.HypervisorBackend64;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
        Logger.getLogger(IpaLoader.class).setLevel(Level.DEBUG);
        Logger.getLogger(HypervisorBackend64.class).setLevel(Level.INFO);
        Logger.getLogger(Dyld64.class).setLevel(Level.INFO);
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
//        builder.addBackendFactory(new Unicorn2Factory(true));
        builder.addBackendFactory(new HypervisorFactory(true));
        Emulator<?> emulator = builder.build();
//        emulator.attach().addBreakPoint(0x1003f8000L + 0x000000000000D7D4);
        emulator.attach().addBreakPoint(0x100458000L + 0x000000000010CFE0);
        emulator.attach().addBreakPoint(0x100458000L + 0x00010d288);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver().setOverride());
        emulator.getSyscallHandler().setVerbose(false);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_osx"));
        long start = System.currentTimeMillis();
        emulator.traceRead(0xfbffffe10L, 0xfbffffe10L + 0x8);
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
