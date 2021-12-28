package com.github.unidbg.android;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class Signal64BxlTest {

    public static void main(String[] args) {
        //Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.DEBUG);
        Signal64BxlTest test = new Signal64BxlTest();
        test.test();
        test.destroy();
    }

    private void destroy() {
        IOUtils.close(emulator);
    }

    private final AndroidEmulator emulator;
    private final Module module;

    private Signal64BxlTest() {
        final File executable = new File("unidbg-android/src/test/native/bxl/example/arm64-v8a/build/ninja/signal64");
        emulator = AndroidEmulatorBuilder
                .for64Bit()
//                .addBackendFactory(new DynarmicFactory(true))
//                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        Memory memory = emulator.getMemory();
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        AndroidResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);

        module = emulator.loadLibrary(executable, true);
    }

    private void test() {

        Logger.getLogger("com.github.unidbg.linux.AndroidSyscallHandler").setLevel(Level.DEBUG);
        emulator.emulateSignal(2);
        emulator.emulateSignal(5);
        int code = module.callEntry(emulator);

        System.err.println("exit code: " + code + ", backend=" + emulator.getBackend());
    }

}
