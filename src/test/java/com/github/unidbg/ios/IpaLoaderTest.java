package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class IpaLoaderTest implements EmulatorConfigurator {

    public void testLoader() {
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
        long start = System.currentTimeMillis();
        LoadedIpa loader = new IpaLoader64(new File("src/test/resources/app/TelegramMessenger-5.11..ipa"),
                new File("target/rootfs/ipa")).load(this);
        Emulator<?> emulator = loader.getEmulator();
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        Module module = loader.getExecutable();
        IClassDumper classDumper = ClassDumper.getInstance(emulator);
        String objcClass = classDumper.dumpClass("TGVideoCameraGLRenderer");
        System.out.println(objcClass);

        Symbol _TelegramCoreVersionString = module.findSymbolByName("_TelegramCoreVersionString");
        Pointer pointer = UnicornPointer.pointer(emulator, _TelegramCoreVersionString.getAddress());
        assert pointer != null;
        System.out.println("_TelegramCoreVersionString=" + pointer.getString(0));
    }

    public static void main(String[] args) {
        IpaLoaderTest test = new IpaLoaderTest();
        test.testLoader();
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String processName, File rootDir) {
        emulator.attach().addBreakPoint(null, 0x103428000L + 0x0000000000A33464L);
    }
}
