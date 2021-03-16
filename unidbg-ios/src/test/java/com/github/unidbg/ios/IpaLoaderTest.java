package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.io.File;

public class IpaLoaderTest implements EmulatorConfigurator {

    public void testLoader() throws Exception {
        long start = System.currentTimeMillis();
        File ipa = new File("unidbg-ios/src/test/resources/app/TelegramMessenger-5.11.ipa");
        if (!ipa.canRead()) {
            ipa = new File("src/test/resources/app/TelegramMessenger-5.11.ipa");
        }
        IpaLoader ipaLoader = new IpaLoader64(ipa, new File("target/rootfs/ipa"));
        ipaLoader.addBackendFactory(new HypervisorFactory(true));
        ipaLoader.addBackendFactory(new DynarmicFactory(true));
        LoadedIpa loader = ipaLoader.load(this);
        final Emulator<?> emulator = loader.getEmulator();
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        loader.callEntry();
        final Module module = loader.getExecutable();
        emulator.attach().run(new DebugRunnable<Void>() {
            @Override
            public Void runWithArgs(String[] args) throws Exception {
                long start = System.currentTimeMillis();
                final IClassDumper classDumper = ClassDumper.getInstance(emulator);
                String objcClass = classDumper.dumpClass("AppDelegate");
                System.out.println("[" + Thread.currentThread().getName() + "]\n" + objcClass);

                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        String objcClass = classDumper.dumpClass("NSDate");
                        System.out.println("[" + Thread.currentThread().getName() + "]\n" + objcClass);
                    }
                });
                thread.start();
                thread.join();

                Symbol _TelegramCoreVersionString = module.findSymbolByName("_TelegramCoreVersionString");
                Pointer pointer = UnidbgPointer.pointer(emulator, _TelegramCoreVersionString.getAddress());
                assert pointer != null;
                System.out.println("_TelegramCoreVersionString=" + pointer.getString(0) + "offset=" + (System.currentTimeMillis() - start) + "ms");
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
