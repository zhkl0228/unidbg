package com.github.unidbg.android;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.TraceFunctionCall;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.FunctionCallListener;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.linux.AndroidSyscallHandler;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class SignalTest {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger(AndroidSyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger(TraceFunctionCall.class).setLevel(Level.INFO);
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
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        Memory memory = emulator.getMemory();
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        AndroidResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        Debugger debugger = emulator.attach();
        module = emulator.loadLibrary(executable, true);
        debugger.traceFunctionCall(module, new FunctionCallListener() {
            @Override
            public void onCall(Emulator<?> emulator, long callerAddress, long functionAddress) {
            }
            @Override
            public void postCall(Emulator<?> emulator, long callerAddress, long functionAddress, Number[] args) {
                System.out.println("onCallFinish caller=" + UnidbgPointer.pointer(emulator, callerAddress) + ", function=" + UnidbgPointer.pointer(emulator, functionAddress));
            }
        });
        emulator.traceCode(module.base, module.base + module.size);
    }

    private void test() {
        long start = System.currentTimeMillis();
        boolean ret = emulator.emulateSignal(17);
        int code = module.callEntry(emulator);
        System.out.println("exit code: " + code + ", ret=" + ret + ", backend=" + emulator.getBackend() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
