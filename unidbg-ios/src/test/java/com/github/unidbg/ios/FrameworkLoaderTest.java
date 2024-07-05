package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.DispatchAsyncCallback;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.hook.MsgSendCallback;
import com.github.unidbg.ios.classdump.ClassDumper;
import com.github.unidbg.ios.classdump.IClassDumper;
import com.github.unidbg.ios.ipa.BundleLoader;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.LoadedBundle;
import com.github.unidbg.ios.objc.NSString;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.UniThreadDispatcher;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class FrameworkLoaderTest implements EmulatorConfigurator, DispatchAsyncCallback, MsgSendCallback {

    public static void main(String[] args) throws Exception {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        FrameworkLoaderTest test = new FrameworkLoaderTest();
        test.testLoader();
    }

    public void testLoader() throws Exception {
        long start = System.currentTimeMillis();
        File dir = new File("unidbg-ios/src/test/resources/example_binaries");
        BundleLoader loader = new BundleLoader(dir, new File("target/rootfs/approov")) {
            @Override
            protected String getBundleIdentifier() {
                return "com.mobillium.papara";
            }
        };
        loader.addBackendFactory(new HypervisorFactory(true));
        loader.addBackendFactory(new DynarmicFactory(true));
        LoadedBundle bundle = loader.load("Approov", this);
        final Emulator<?> emulator = bundle.getEmulator();
        final ObjC objc = ObjC.getInstance(emulator);
        System.out.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        final HookLoader hookLoader = HookLoader.load(emulator);
        hookLoader.hookDispatchAsync(this);
        final ObjcClass cApproov = objc.getClass("Approov");
        String initialConfig = "#447440#GLWOzh88IjYKBLg5szMsGeOR4VhqPwen5Qrq0rNtdQs=";
        boolean success = cApproov.callObjcInt("initialize:updateConfig:comment:error:",
                objc.newString(initialConfig),
                null, null, null) != 0;
        if (!success) {
            throw new IllegalStateException("Approov.initialize failed.");
        }
        emulator.attach().run(new DebugRunnable<Void>() {
            @Override
            public Void runWithArgs(String[] args) {
                final IClassDumper classDumper = ClassDumper.getInstance(emulator);
                String objcClass = classDumper.dumpClass("Approov");
                System.out.println("[" + Thread.currentThread().getName() + "]\n" + objcClass);
                NSString sdkId = cApproov.callObjc("getSDKID").toNSString();
                NSString deviceID = cApproov.callObjc("getDeviceID").toNSString();
                System.out.println("sdkId=" + sdkId.getString() + ", deviceID=" + deviceID.getString());

                hookLoader.hookObjcMsgSend(FrameworkLoaderTest.this);
                Logger.getLogger(UniThreadDispatcher.class).setLevel(Level.TRACE);
                Logger.getLogger("com.github.unidbg.ios.debug").setLevel(Level.DEBUG);
                ObjcObject result = cApproov.callObjc("fetchApproovTokenAndWait:", objc.newString("api.papara.com"));
                System.out.println("fetchApproovTokenAndWait result=" + result);
                return null;
            }
        });
    }

    @Override
    public void onMsgSend(Emulator<?> emulator, boolean systemClass, String className, String cmd, Pointer lr) {
        System.out.println("onMsgSend [" + className + " " + cmd + "] LR=" + lr);
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        SyscallHandler<?> syscallHandler = emulator.getSyscallHandler();
        syscallHandler.setVerbose(false);
        syscallHandler.setEnableThreadDispatcher(true);
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }

    @Override
    public Result canDispatch(Emulator<?> emulator, Pointer dq, Pointer fun, boolean is_barrier_async) {
        long address = UnidbgPointer.nativeValue(fun);
        Module module = emulator.getMemory().findModuleByAddress(address);
        if ("Approov".equals(module.name)) {
            long offset = address - module.base;
            if (offset == 0x4c0e0) {
                return Result.thread_run;
            }
            if (offset == 0xd2d4) {
                return Result.thread_run;
            }
        }
        System.out.println("canDispatch dq=" + dq + ", fun=" + fun + ", is_barrier_async=" + is_barrier_async);
        return Result.skip;
    }

}
