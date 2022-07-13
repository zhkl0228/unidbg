package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.DispatchAsyncCallback;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class LineApp implements EmulatorConfigurator, HookListener, DispatchAsyncCallback {

    public static void main(String[] args) {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
        LineApp line = new LineApp(new File(FileUtils.getUserDirectory(), "Documents/Line/app/jp.naver.line_12.10.0.ipa"), false);
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
        IpaLoader loader = new IpaLoader64(ipa, rootDir) {
            /*@Override
            protected LibraryResolver createLibraryResolver() {
                return new CoreSimulatorResolver(new File("/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS.simruntime/Contents/Resources/RuntimeRoot"));
            }*/
        };
        loader.addBackendFactory(new HypervisorFactory(true));
        loader.useOverrideResolver();
        return loader;
    }

    protected void init() {
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
        emulator.attach().addBreakPoint(0x10b0ec050L);
    }

    @Override
    public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
    }

}
