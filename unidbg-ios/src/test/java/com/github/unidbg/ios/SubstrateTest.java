package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.ios.ipa.NSUserDefaultsResolver;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class SubstrateTest extends EmulatorTest<ARMEmulator<DarwinFileIO>> {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected ARMEmulator<DarwinFileIO> createARMEmulator() {
        return DarwinEmulatorBuilder.for32Bit()
                .setProcessName("com.substrate.test")
                .setRootDir(new File("target/rootfs/substrate"))
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
    }

    public void testIgnore() {
    }

    private void processMS() {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setObjcRuntime(true);
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        long start;
        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/libsubstrate.dylib"));

        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);

        start = System.currentTimeMillis();

//        emulator.traceRead();
//        emulator.attach().addBreakPoint(null, 0x401495dc);
//        emulator.traceCode();

        /*whale.inlineHookFunction(module.findSymbolByName("_malloc"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(0);
                System.err.println("onCall _malloc size=" + size + ", origin=" + UnicornPointer.pointer(emulator, originFunction));
                return HookStatus.RET(emulator, originFunction);
            }
        });*/

//        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
//        emulator.traceCode();
        /*whale.importHookFunction("_strcmp", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer pointer1 = context.getPointerArg(0);
                Pointer pointer2 = context.getPointerArg(1);
                System.out.println("IWhale strcmp str1=" + (pointer1 == null ? null : pointer1.getString(0)) + ", str2=" + (pointer2 == null ? null : pointer2.getString(0)) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator, originFunction);
            }
        });*/

        // emulator.attach().addBreakPoint(module, 0x00b608L);
//        emulator.traceCode();
        Number number = symbol.call(emulator, "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        long ret = number.intValue() & 0xffffffffL;
        System.err.println("_MSGetImageByName ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        symbol = module.findSymbolByName("_MSFindSymbol");
        assertNotNull(symbol);
        start = System.currentTimeMillis();
//         emulator.traceCode();
        number = symbol.call(emulator, UnidbgPointer.pointer(emulator, ret), "_MSGetImageByName");
        ret = number.intValue() & 0xffffffffL;
        System.err.println("_MSFindSymbol ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        HookLoader.load(emulator).hookObjcMsgSend(null);

        start = System.currentTimeMillis();
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger(DarwinSyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.ios.debug").setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.thread").setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.ios.kevent").setLevel(Level.INFO);
        loader.getExecutableModule().callEntry(emulator);
        System.err.println("callExecutableEntry offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        Map<String, Object> map = new HashMap<>();
        map.put("name", getClass().getName());
        emulator.getSyscallHandler().addIOResolver(new NSUserDefaultsResolver("unidbg", map));

        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));
    }

    public static void main(String[] args) throws Exception {
        SubstrateTest test = new SubstrateTest();
        test.setUp();
        test.processMS();
        test.tearDown();
    }

}
