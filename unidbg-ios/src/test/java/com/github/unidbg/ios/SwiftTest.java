package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.ios.thread.HookDispatcherLoader;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class SwiftTest {

    public static void main(String[] args) throws IOException {
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
        builder.addBackendFactory(new HypervisorFactory(true));
        builder.addBackendFactory(new DynarmicFactory(true));
        Emulator<DarwinFileIO> emulator = builder.build();

        Memory memory = emulator.getMemory();
        memory.addHookListener(new SymbolResolver(emulator));
        memory.setLibraryResolver(new DarwinResolver());
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/swift_test"));
        HookDispatcherLoader.load(emulator);
        long start = System.currentTimeMillis();
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(DarwinSyscallHandler.class).setLevel(Level.INFO);
        int ret = module.callEntry(emulator);
        System.err.println("testSwift backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
