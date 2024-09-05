package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.DispatchAsyncCallback;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.memory.Memory;

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
        HookLoader.load(emulator).hookDispatchAsync((emulator1, dq, fun, is_barrier_async) -> {
            System.out.println("canDispatch dq=" + dq + ", fun=" + fun + ", is_barrier_async=" + is_barrier_async);
            return DispatchAsyncCallback.Result.direct_run;
        });
        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator);
        System.err.println("testSwift backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
