package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.dmg.DmgLoader;
import com.github.unidbg.ios.dmg.DmgLoader64;
import com.github.unidbg.ios.dmg.LoadedDmg;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class DmgLoaderTest implements EmulatorConfigurator {

    public void testLoader() throws Exception {
        long start = System.currentTimeMillis();
        File dmg = new File(FileUtils.getUserDirectory(), "Downloads/WeChat.app");
        DmgLoader ipaLoader = new DmgLoader64(dmg, new File("target/rootfs/dmg"));
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
        LoadedDmg loader = ipaLoader.load(this);
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
        DmgLoaderTest test = new DmgLoaderTest();
        test.testLoader();
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        emulator.attach().addBreakPoint(0x108127208L);
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }
}
