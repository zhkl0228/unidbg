package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.thread.BaseTask;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(BaseTask.class).setLevel(Level.INFO);
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
        builder.addBackendFactory(new HypervisorFactory(true));
        Emulator<DarwinFileIO> emulator = builder.build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver().setOverride());
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_osx"));
        long start = System.currentTimeMillis();
        emulator.traceRead(0xfbffffd30L, 0xfbffffd30L + 0x8);
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
