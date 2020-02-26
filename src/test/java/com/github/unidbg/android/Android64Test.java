package com.github.unidbg.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.android.struct.File64;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.struct.Stat64;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class Android64Test {

    public static void main(String[] args) throws IOException {
        Logger.getLogger("com.github.unidbg.linux.ARM64SyscallHandler").setLevel(Level.INFO);
        new Android64Test().test();
    }

    private final Emulator<?> emulator;
    private final Module module;

    private Android64Test() throws IOException {
        File executable = new File("src/test/native/android/libs/arm64-v8a/test");
        emulator = new AndroidARM64Emulator(executable.getName(), new File("target/rootfs"));
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);

        memory.setCallInitFunction();

//        emulator.traceCode();
        module = emulator.loadLibrary(executable);

        {
            Pointer pointer = memory.allocateStack(0x100);
            System.out.println(new Stat64(pointer));
        }
    }

    private void test() {
//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x40080648);
        System.err.println("exit code: " + module.callEntry(emulator));

        Symbol __sF = module.findSymbolByName("__sF", true);
        Pointer pointer = UnicornPointer.pointer(emulator, __sF.getAddress());
        assert pointer != null;

        File64 stdin = new File64(pointer);
        System.out.println(stdin);

        pointer = pointer.share(stdin.size());
        File64 stdout = new File64(pointer);
        System.out.println(stdout);

        pointer = pointer.share(stdout.size());
        File64 stderr = new File64(pointer);
        System.out.println(stderr);
    }

}
