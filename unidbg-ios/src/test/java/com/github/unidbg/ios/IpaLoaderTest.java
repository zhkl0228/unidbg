package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.dynarmic.DynarmicLoader;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.util.concurrent.Callable;

public class IpaLoaderTest implements EmulatorConfigurator {

    static {
        DynarmicLoader.useDynarmic();
    }

    public void testLoader() throws Exception {
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.INFO);
        long start = System.currentTimeMillis();
        LoadedIpa loader = new IpaLoader64(new File("unidbg-ios/src/test/resources/app/TelegramMessenger-5.11.ipa"),
                new File("target/rootfs/ipa")).load(this);
        final Emulator<?> emulator = loader.getEmulator();
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        loader.callEntry();
        final Module module = loader.getExecutable();
        emulator.attach().run(new Callable<Void>() {
            @Override
            public Void call() {
                IClassDumper classDumper = ClassDumper.getInstance(emulator);
                String objcClass = classDumper.dumpClass("AppDelegate");
                System.out.println(objcClass);

                Symbol _TelegramCoreVersionString = module.findSymbolByName("_TelegramCoreVersionString");
                Pointer pointer = UnidbgPointer.pointer(emulator, _TelegramCoreVersionString.getAddress());
                assert pointer != null;
                System.out.println("_TelegramCoreVersionString=" + pointer.getString(0));
                return null;
            }
        });
    }

    public static void main(String[] args) throws Exception {
        IpaLoaderTest test = new IpaLoaderTest();
        test.testLoader();
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }
}
