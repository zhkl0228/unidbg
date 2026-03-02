package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.arm.backend.hypervisor.Hypervisor;
import com.github.unidbg.debugger.McpTool;
import com.github.unidbg.debugger.McpToolkit;
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

    private Emulator<?> emulator;
    private Module module;

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
        emulator = loader.getEmulator();
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        loader.callEntry();
        module = loader.getExecutable();

        McpToolkit toolkit = new McpToolkit();
        toolkit.addTool(new McpTool() {
            @Override public String name() { return "dumpClass"; }
            @Override public String description() { return "Dump an ObjC class definition by name"; }
            @Override public String[] paramNames() { return new String[]{"className"}; }
            @Override public void execute(String[] params) {
                String className = params.length > 0 ? params[0] : "AppDelegate";
                IClassDumper classDumper = ClassDumper.getInstance(emulator);
                System.out.println("dumpClass(" + className + "):\n" + classDumper.dumpClass(className));
            }
        });
        toolkit.addTool(new McpTool() {
            @Override public String name() { return "readVersion"; }
            @Override public String description() { return "Read the TelegramCoreVersionString from the executable"; }
            @Override public void execute(String[] params) throws InterruptedException {
                Symbol sym = module.findSymbolByName("_TelegramCoreVersionString");
                if (sym != null) {
                    Pointer pointer = UnidbgPointer.pointer(emulator, sym.getAddress());
                    if (pointer != null) {
                        System.out.println("_TelegramCoreVersionString=" + pointer.getString(0));
                    }
                    if (emulator.getBackend().isHypervisor()) {
                        IClassDumper classDumper = ClassDumper.getInstance(emulator);
                        Thread thread = new Thread(() -> {
                            String objcClass1 = classDumper.dumpClass("NSDate");
                            System.out.printf("[%s]maxVcpuCount=%d\n%s%n", Thread.currentThread().getName(), Hypervisor.getMaxVcpuCount(), objcClass1);
                        });
                        thread.start();
                        thread.join();
                    }
                } else {
                    System.out.println("Symbol _TelegramCoreVersionString not found");
                }
            }
        });
        toolkit.run(emulator.attach());
        emulator.close();
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
