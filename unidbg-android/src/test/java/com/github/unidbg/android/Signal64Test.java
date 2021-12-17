package com.github.unidbg.android;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class Signal64Test {

    public static void main(String[] args) throws IOException {
        Signal64Test test = new Signal64Test();
        test.test();
        test.destroy();
    }

    private void destroy() {
        IOUtils.close(emulator);
    }

    private final AndroidEmulator emulator;
    private final Module module;

    private Signal64Test() {
        final File executable = new File("unidbg-android/src/test/native/android/libs/arm64-v8a/signal");
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new HypervisorFactory(true))
                .build();
        Memory memory = emulator.getMemory();
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        AndroidResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);

        module = emulator.loadLibrary(executable, true);
    }

    private void test() {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(ARM64SyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.linux.AndroidSyscallHandler").setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.thread").setLevel(Level.INFO);
        emulator.emulateSignal(29);
        int code = module.callEntry(emulator);
        System.err.println("exit code: " + code + ", backend=" + emulator.getBackend());
    }

}
