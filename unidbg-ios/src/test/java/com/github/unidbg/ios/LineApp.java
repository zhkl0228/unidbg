package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.DispatchAsyncCallback;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;

import java.io.File;

public class LineApp implements EmulatorConfigurator, HookListener, DispatchAsyncCallback {

    public static void main(String[] args) throws Exception {
        LineApp line = new LineApp(new File(FileUtils.getUserDirectory(), "Documents/Line/app/jp.naver.line_12.10.0.ipa"), true);
        line.test();
    }

    private void test() throws Exception {
        emulator.attach().run(new DebugRunnable<Object>() {
            @Override
            public Object runWithArgs(String[] args) {
                return null;
            }
        });
    }

    protected final Emulator<?> emulator;
    protected final ObjC objc;

    private LineApp(File ipa, boolean callFinishLaunchingWithOptions) {
        super();

        File rootDir = new File("target/rootfs/line/ios");
        IpaLoader ipaLoader = createLoader(ipa, rootDir);
        LoadedIpa loadedIpa = ipaLoader.load(this);

        emulator = loadedIpa.getEmulator();
        objc = ObjC.getInstance(emulator);

        HookLoader.load(emulator).hookDispatchAsync(this);
        init();
        loadedIpa.setCallFinishLaunchingWithOptions(callFinishLaunchingWithOptions);
        loadedIpa.callEntry();
    }

    protected IpaLoader createLoader(File ipa, File rootDir) {
        IpaLoader loader = new IpaLoader64(ipa, rootDir);
        loader.addBackendFactory(new HypervisorFactory(true));
        loader.useOverrideResolver();
        return loader;
    }

    protected void init() {
        ISubstrate substrate = Substrate.getInstance(emulator);

        ObjcClass cPLCrashReporter = objc.getClass("PLCrashReporter");
        substrate.hookMessageEx(cPLCrashReporter.getMeta(), objc.registerName("initialize"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [PLCrashReporter initialize]");
                return HookStatus.LR(emulator, 0L);
            }
        });
        ObjcClass cLineSearchProxy = objc.getClass("LINE.LineSearchProxy");
        substrate.hookMessageEx(cLineSearchProxy, objc.registerName("init"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [LineSearchProxy init]");
                return HookStatus.LR(emulator, 0L);
            }
        });
        ObjcClass cLineServiceManager = objc.getClass("LineServiceManager");
        substrate.hookMessageEx(cLineServiceManager.getMeta(), objc.registerName("setupNetworking"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [LineServiceManager setupNetworking]");
                return HookStatus.LR(emulator, 0L);
            }
        });
        ObjcClass cNLAuthenticationManager = objc.getClass("NLAuthenticationManager");
        substrate.hookMessageEx(cNLAuthenticationManager, objc.registerName("getAuthenticationToken"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [NLAuthenticationManager getAuthenticationToken]");
                return HookStatus.LR(emulator, 0L);
            }
        });
        substrate.hookMessageEx(cNLAuthenticationManager, objc.registerName("deleteAuthenticationTokenAndPasscode"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [NLAuthenticationManager deleteAuthenticationTokenAndPasscode]");
                return HookStatus.LR(emulator, 0L);
            }
        });
        ObjcClass cAppDelegate = objc.getClass("LINE.AppDelegate");
        substrate.hookMessageEx(cAppDelegate, objc.registerName("showWelcomeViewControllerWithAnimated:completion:"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [AppDelegate showWelcomeViewControllerWithAnimated]");
                return HookStatus.LR(emulator, 0L);
            }
        });
        ObjcClass cGeneralSettingsManager = objc.getClass("LineGeneralSettingsSubsystem.GeneralSettingsManager");
        substrate.hookMessageEx(cGeneralSettingsManager, objc.registerName("init"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("fake [GeneralSettingsManager init]");
                return HookStatus.LR(emulator, 0L);
            }
        });
    }

    @Override
    public boolean canDispatch(Pointer dq, Pointer fun) {
        return false;
    }

    @Override
    public long hook(SvcMemory svcMemory, String libraryName, String symbolName, long old) {
        return 0;
    }

    @Override
    public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath, File rootDir, String bundleIdentifier) {
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getMemory().addHookListener(this);
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }

}
