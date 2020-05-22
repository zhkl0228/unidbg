package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class IpaLoaderTest {

    public void testLoader() throws Exception {
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
        long start = System.currentTimeMillis();
        IpaLoader loader = IpaLoader.load64(new File("src/test/resources/app/TelegramMessenger-5.11..ipa"),
                new File("target/rootfs/ipa"));
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

    public static void main(String[] args) throws Exception {
        IpaLoaderTest test = new IpaLoaderTest();
        test.testLoader();
    }

}
