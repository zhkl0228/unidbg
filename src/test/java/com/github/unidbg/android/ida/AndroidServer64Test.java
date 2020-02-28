package com.github.unidbg.android.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class AndroidServer64Test {

    public static void main(String[] args) throws IOException {
        new AndroidServer64Test().test();
    }

    private final Emulator<?> emulator;
    private final Module module;

    private AndroidServer64Test() throws IOException {
        File executable = new File("src/test/resources/example_binaries/ida/android_server64_7.4");
        emulator = new AndroidARM64Emulator(executable.getName(), new File("target/rootfs/ida"));
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(23);
        memory.setLibraryResolver(resolver);

        memory.setCallInitFunction();

        module = emulator.loadLibrary(executable);
    }

    private void test() {
        System.err.println("exit code: " + module.callEntry(emulator));
    }

}
