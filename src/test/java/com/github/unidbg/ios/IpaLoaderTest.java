package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.android.EmulatorTest;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class IpaLoaderTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARM64Emulator();
    }

    public void testLoader() throws Exception {
        emulator.getMemory().setCallInitFunction();
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.INFO);
//        emulator.attach(0x102a594f0L - 1000, 0x102a594f0L + 1000).addBreakPoint(null, 0x102a594f0L);
        IpaLoader loader = IpaLoader.load(emulator, new File("src/test/resources/app/TelegramMessenger-5.11..ipa"), true,
                "TelegramCore", "TelegramUI");
        Module module = loader.getExecutable();
        assertNotNull(module);
        IClassDumper classDumper = ClassDumper.getInstance(emulator);
        String objcClass = classDumper.dumpClass("TGVideoCameraGLRenderer");
        System.out.println(objcClass);

        Symbol _TelegramCoreVersionString = module.findSymbolByName("_TelegramCoreVersionString");
        Pointer pointer = UnicornPointer.pointer(emulator, _TelegramCoreVersionString.getAddress());
        assertNotNull(pointer);
        System.out.println("_TelegramCoreVersionString=" + pointer.getString(0));
    }

    public static void main(String[] args) throws Exception {
        IpaLoaderTest test = new IpaLoaderTest();
        test.setUp();
        test.testLoader();
        test.tearDown();
    }

}
