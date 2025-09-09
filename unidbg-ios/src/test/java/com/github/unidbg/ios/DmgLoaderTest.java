package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.dmg.DmgLoader;
import com.github.unidbg.ios.dmg.DmgLoader64;
import com.github.unidbg.ios.dmg.LoadedDmg;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import org.apache.commons.io.FileUtils;

import java.io.File;

public class DmgLoaderTest implements EmulatorConfigurator, ModuleListener {

    public void testLoader() throws Exception {
        long start = System.currentTimeMillis();
        File dmg = new File(FileUtils.getUserDirectory(), "Downloads/WeChat.app");
        DmgLoader ipaLoader = new DmgLoader64(dmg, new File("target/rootfs/dmg"));
        ipaLoader.addBackendFactory(new HypervisorFactory(false));
        ipaLoader.useOverrideResolver();
        LoadedDmg loader = ipaLoader.load(this);
        final Emulator<?> emulator = loader.getEmulator();
        init(emulator);
        System.err.println("load backend=" + emulator.getBackend() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        loader.callEntry();
        emulator.attach().run((DebugRunnable<Void>) args -> {
            long start1 = System.currentTimeMillis();
            final IClassDumper classDumper = ClassDumper.getInstance(emulator);
            String objcClass = classDumper.dumpClass("AppDelegate");
            System.out.println("[" + Thread.currentThread().getName() + "]\n" + objcClass);

            Thread thread = new Thread(() -> {
                String objcClass1 = classDumper.dumpClass("NSDate");
                System.out.println("[" + Thread.currentThread().getName() + "]\n" + objcClass1);
            });
            thread.start();
            thread.join();

            System.out.println("offset=" + (System.currentTimeMillis() - start1) + "ms");
            return null;
        });
    }

    private void init(Emulator<?> emulator) {
    }

    public static void main(String[] args) throws Exception {
        DmgLoaderTest test = new DmgLoaderTest();
        test.testLoader();
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getMemory().addModuleListener(this);
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }

    @Override
    public void onLoaded(Emulator<?> emulator, Module module) {
    }
}
