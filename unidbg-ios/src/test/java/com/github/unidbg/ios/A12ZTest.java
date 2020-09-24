package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ios.file.Stdout;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    public static void main(String[] args) throws IOException {
        Logger.getLogger(Stdout.class).setLevel(Level.DEBUG);
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
        Emulator<?> emulator = new DarwinARMEmulator();
        emulator.getMemory().setLibraryResolver(new DarwinResolver());
        emulator.getSyscallHandler().setVerbose(true);

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_ios"));

        emulator.attach().addBreakPoint(null, 0x0000000100003F40L);
        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
