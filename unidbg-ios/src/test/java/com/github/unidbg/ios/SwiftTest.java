package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.DispatchAsyncCallback;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class SwiftTest {

    public static void main(String[] args) throws IOException {
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
        builder.addBackendFactory(new HypervisorFactory(true));
        builder.addBackendFactory(new DynarmicFactory(true));
        final Emulator<DarwinFileIO> emulator = builder.build();

        Memory memory = emulator.getMemory();
        memory.addHookListener(new SymbolResolver(emulator));
        memory.setLibraryResolver(new DarwinResolver().setOverride());
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/swift_test"));
        HookLoader.load(emulator).hookDispatchAsync(new DispatchAsyncCallback() {
            @Override
            public boolean canDispatch(Pointer dq, Pointer fun) {
                System.out.println("canDispatch dq=" + dq + ", fun=" + fun);
                return UnidbgPointer.nativeValue(fun) != 0x100004a24L;
            }
        });
        long start = System.currentTimeMillis();
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(DarwinSyscallHandler.class).setLevel(Level.INFO);
        int ret = module.callEntry(emulator);
        System.err.println("testSwift backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
