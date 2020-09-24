package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    public static void main(String[] args) throws IOException {
        Emulator<?> emulator = new DarwinARM64Emulator();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        emulator.getSyscallHandler().setVerbose(true);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_osx"));
        Module cm = memory.findModule("libsystem_c.dylib");
        Symbol setvbuf = cm.findSymbolByName("_setvbuf", false);
        Symbol __stdoutp = cm.findSymbolByName("___stdoutp", false);
        Symbol __stderrp = cm.findSymbolByName("___stderrp", false);
        Pointer stdoutp = UnicornPointer.pointer(emulator, __stdoutp.getAddress());
        Pointer stderrp = UnicornPointer.pointer(emulator, __stderrp.getAddress());
        assert stdoutp != null && stderrp != null;
        final int _IONBF = 2;
        setvbuf.call(emulator, stdoutp.getPointer(0), null, _IONBF, 0);
        setvbuf.call(emulator, stderrp.getPointer(0), null, _IONBF, 0);

        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
