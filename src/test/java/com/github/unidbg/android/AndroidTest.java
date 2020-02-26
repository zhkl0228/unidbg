package com.github.unidbg.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.android.struct.File32;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.struct.Stat32;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

public class AndroidTest {

    public static void main(String[] args) throws IOException {
        new AndroidTest().test();
    }

    private final Emulator<?> emulator;
    private final Module module;

    private AndroidTest() throws IOException {
        File executable = new File("src/test/native/android/libs/armeabi-v7a/test");
        emulator = new AndroidARMEmulator(executable.getName(), new File("target/rootfs"));
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        memory.setCallInitFunction();

        module = emulator.loadLibrary(executable);

        {
            Pointer pointer = memory.allocateStack(0x100);
            System.out.println(new Stat32(pointer));
        }
    }

    private void test() {
        System.err.println("exit code: " + module.callEntry(emulator));

        Symbol __sF = module.findSymbolByName("__sF", true);
        Pointer pointer = UnicornPointer.pointer(emulator, __sF.getAddress());
        assert pointer != null;

        File32 stdin = new File32(pointer);
        System.out.println(stdin);

        pointer = pointer.share(stdin.size());
        File32 stdout = new File32(pointer);
        System.out.println(stdout);

        pointer = pointer.share(stdout.size());
        File32 stderr = new File32(pointer);
        System.out.println(stderr);
    }

}
