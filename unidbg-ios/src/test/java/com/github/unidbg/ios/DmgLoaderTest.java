package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.dmg.DmgLoader;
import com.github.unidbg.ios.dmg.DmgLoader64;
import com.github.unidbg.ios.dmg.LoadedDmg;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class DmgLoaderTest implements EmulatorConfigurator, ModuleListener {

    public void testLoader() throws Exception {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
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

                System.out.println("offset=" + (System.currentTimeMillis() - start) + "ms");
                return null;
            }
        });
    }

    private void init(Emulator<?> emulator) {
        ObjC objc = ObjC.getInstance(emulator);
        ISubstrate substrate = Substrate.getInstance(emulator);

        ObjcClass cGSMux = objc.getClass("GSMux");
        substrate.hookMessageEx(cGSMux.getMeta(), objc.registerName("switcherOpen"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake +[GSMux switcherOpen]");
                return HookStatus.LR(emulator, 0);
            }
        });

        ObjcClass cGSGPU = objc.getClass("GSGPU");
        substrate.hookMessageEx(cGSGPU.getMeta(), objc.registerName("registerForGPUChangeNotifications:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake +[GSGPU registerForGPUChangeNotifications]");
                return HookStatus.LR(emulator, 0);
            }
        });
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
