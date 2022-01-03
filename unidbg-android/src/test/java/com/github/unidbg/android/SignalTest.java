package com.github.unidbg.android;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class SignalTest {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.linux.AndroidSyscallHandler").setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.thread").setLevel(Level.INFO);

        SignalTest test = new SignalTest();
        test.test();
        test.destroy();
    }

    private void destroy() {
        IOUtils.close(emulator);
    }

    private final AndroidEmulator emulator;
    private final Module module;

    private SignalTest() {
        final File executable = new File("unidbg-android/src/test/native/android/libs/armeabi-v7a/signal");
        emulator = AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        Memory memory = emulator.getMemory();
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        AndroidResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        module = emulator.loadLibrary(executable, true);
    }

    private void test() {
        emulator.emulateSignal(17);
        int code = module.callEntry(emulator);
        System.err.println("exit code: " + code + ", backend=" + emulator.getBackend());
    }

}
