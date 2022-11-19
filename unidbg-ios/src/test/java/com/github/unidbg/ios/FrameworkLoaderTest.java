package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.BundleLoader;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.LoadedBundle;
import com.github.unidbg.ios.objc.NSString;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.spi.SyscallHandler;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class FrameworkLoaderTest implements EmulatorConfigurator {

    public static void main(String[] args) throws Exception {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
        FrameworkLoaderTest test = new FrameworkLoaderTest();
        test.testLoader();
    }

    public void testLoader() throws Exception {
        long start = System.currentTimeMillis();
        File dir = new File("unidbg-ios/src/test/resources/example_binaries");
        BundleLoader loader = new BundleLoader(dir, new File("target/rootfs/approov"));
        loader.addBackendFactory(new HypervisorFactory(true));
        loader.addBackendFactory(new DynarmicFactory(true));
        LoadedBundle bundle = loader.load("Approov", this);
        final Emulator<?> emulator = bundle.getEmulator();
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        emulator.attach().run(new DebugRunnable<Void>() {
            @Override
            public Void runWithArgs(String[] args) {
                final IClassDumper classDumper = ClassDumper.getInstance(emulator);
                String objcClass = classDumper.dumpClass("Approov");
                System.out.println("[" + Thread.currentThread().getName() + "]\n" + objcClass);
                ObjC objc = ObjC.getInstance(emulator);
                ObjcClass cApproov = objc.getClass("Approov");
                NSString sdkId = cApproov.callObjc("getSDKID").toNSString();
                System.out.println("sdkId=" + sdkId.getString());
                return null;
            }
        });
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        SyscallHandler<?> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.setVerbose(false);
        syscallHandler.setEnableThreadDispatcher(false);
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }

}
