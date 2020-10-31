package com.github.unidbg.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.dynarmic.DynarmicLoader;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.struct.Dirent;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

public class AndroidTest {

    static {
        DynarmicLoader.useDynarmic();
    }

    public static void main(String[] args) throws IOException {
        new AndroidTest().test();
    }

    private final Emulator<?> emulator;
    private final Module module;

    private static class MyARMSyscallHandler extends ARM32SyscallHandler {
        private MyARMSyscallHandler(SvcMemory svcMemory) {
            super(svcMemory);
        }
        @Override
        protected int fork(Emulator<?> emulator) {
            return emulator.getPid();
        }
    }

    private AndroidTest() throws IOException {
        File executable = new File("unidbg-android/src/test/native/android/libs/armeabi-v7a/test");
        emulator = new AndroidARMEmulator(executable.getName(), new File("target/rootfs")) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new MyARMSyscallHandler(svcMemory);
            }
        };
        Memory memory = emulator.getMemory();
        emulator.getSyscallHandler().setVerbose(false);
        LibraryResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        module = emulator.loadLibrary(executable, true);

        {
            Pointer pointer = memory.allocateStack(0x100);
            System.out.println(new Dirent(pointer));
        }
    }

    private void test() {
//        Logger.getLogger("com.github.unidbg.linux.ARM32SyscallHandler").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.unix.UnixSyscallHandler").setLevel(Level.DEBUG);
        System.err.println("exit code: " + module.callEntry(emulator));
    }

}
