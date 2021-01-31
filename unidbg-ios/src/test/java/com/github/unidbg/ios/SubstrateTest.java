package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.ios.ipa.NSUserDefaultsResolver;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
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
                .build();
    }

    public void testIgnore() {
    }

    private void processMS() {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        loader.setObjcRuntime(true);
//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x402ffd10);
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.INFO);
        long start;
        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/libsubstrate.dylib"));

//        emulator.traceCode();

        /*IFishHook fishHook = FishHook.getInstance(emulator);
        fishHook.rebindSymbol("memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer dest = context.getPointerArg(0);
                Pointer src = context.getPointerArg(1);
                int size = context.getIntArg(2);
                System.err.println("fishhook memcpy dest=" + dest + ", src=" + src + ", size=" + size);
                return HookStatus.RET(emulator, originFunction);
            }
        });*/

//        IWhale whale = Whale.getInstance(emulator);
        /*whale.WImportHookFunction("_malloc", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                int size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                System.err.println("IWhale hook _malloc size=" + size);
                return HookStatus.RET(unicorn, originFunction);
            }
        });*/

//        Logger.getLogger("com.github.unidbg.ios.ARM32SyscallHandler").setLevel(Level.DEBUG);
        Symbol _malloc_zone_malloc = module.findSymbolByName("_malloc_zone_malloc");
        Dobby.getInstance(emulator).replace(_malloc_zone_malloc, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer zone = context.getPointerArg(0);
                int size = context.getIntArg(1);
                System.err.println("_malloc_zone_malloc zone=" + zone + ", size=" + size);
                return HookStatus.RET(emulator, originFunction);
            }
        });

        IHookZz hookZz = HookZz.getInstance(emulator);
        Symbol _free = module.findSymbolByName("_free");
//        emulator.attach().addBreakPoint(null, _free.getAddress());
        hookZz.instrument(_free, new InstrumentCallback<RegisterContext>() {
            @Override
            public void dbiCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
                System.err.println("dbiCall _free=" + ctx.getPointerArg(0));
            }
        });

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
        Number[] numbers = symbol.call(emulator, "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        long ret = numbers[0].intValue() & 0xffffffffL;
        System.err.println("_MSGetImageByName ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        symbol = module.findSymbolByName("_MSFindSymbol");
        assertNotNull(symbol);
        start = System.currentTimeMillis();
//         emulator.traceCode();
        numbers = symbol.call(emulator, UnidbgPointer.pointer(emulator, ret), "_MSGetImageByName");
        ret = numbers[0].intValue() & 0xffffffffL;
        System.err.println("_MSFindSymbol ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        HookLoader.load(emulator).hookObjcMsgSend(null);

        start = System.currentTimeMillis();
//        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.ios.ARM32SyscallHandler").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.ios.MachOLoader").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.spi.AbstractLoader").setLevel(Level.DEBUG);
//        emulator.attach(0x4128F000, 0x41339000).addBreakPoint(null, 0x4128F000 + 0x0001E9B8);

//        emulator.attach(0xfffe0000L, 0xfffe0000L + 0x10000).addBreakPoint(null, 0xfffe0080L);
//        emulator.traceCode(0xfffe0000L, 0xfffe0000L + 0x10000);
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.INFO);
//        Logger.getLogger("com.github.unidbg.ios.ARM32SyscallHandler").setLevel(Level.DEBUG);
        Logger.getLogger("com.github.unidbg.ios.debug").setLevel(Level.DEBUG);
        loader.getExecutableModule().callEntry(emulator);
        System.err.println("callExecutableEntry offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        Map<String, Object> map = new HashMap<>();
        map.put("name", getClass().getName());
        emulator.getSyscallHandler().addIOResolver(new NSUserDefaultsResolver("unidbg", map));

        emulator.getSyscallHandler().setVerbose(false);
    }

    public static void main(String[] args) throws Exception {
        SubstrateTest test = new SubstrateTest();
        test.setUp();
        test.processMS();
        test.tearDown();
    }

}
