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
import com.github.unidbg.hook.MsgSendCallback;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.Dobby;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.InstrumentCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class Substrate64Test extends EmulatorTest<ARMEmulator<DarwinFileIO>> implements MsgSendCallback {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected ARMEmulator<DarwinFileIO> createARMEmulator() {
        return DarwinEmulatorBuilder.for64Bit()
                .addEnv("CFFIXED_USER_HOME=/var/mobile")
                .setRootDir(new File("target/rootfs/substrate"))
                .build();
    }

    public void testMS() {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
//        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(null, 0x100dd29b4L);
        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.INFO);
//        Logger.getLogger("com.github.unidbg.ios.ARM64SyscallHandler").setLevel(Level.DEBUG);
//        emulator.traceCode();
        loader.setObjcRuntime(true);
        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/libsubstrate.dylib"));

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
//        Logger.getLogger("com.github.emulator.ios.ARM64SyscallHandler").setLevel(Level.DEBUG);
//        Module libwhale = emulator.getMemory().findModule("libwhale.dylib");
//        emulator.attach(libwhale.base, libwhale.base + libwhale.size).addBreakPoint(libwhale, 0x0000184b0);
        /*whale.importHookFunction("_malloc", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                int size = context.getIntArg(0);
                System.err.println("IWhale hook _malloc size=" + size);
                return HookStatus.RET(emulator, originFunction);
            }
        });*/

        IHookZz hookZz = Dobby.getInstance(emulator);
        Symbol malloc_zone_malloc = module.findSymbolByName("_malloc_zone_malloc");
//        Module libhookzz = emulator.getMemory().findModule("libhookzz.dylib");
//        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(libhookzz, 0x0000000000007850);
//        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
//        Logger.getLogger(DarwinSyscallHandler.class).setLevel(Level.DEBUG);
//        emulator.traceCode(libhookzz.base, libhookzz.base + libhookzz.size);
        hookZz.replace(malloc_zone_malloc, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer zone = context.getPointerArg(0);
                int size = context.getIntArg(1);
                System.err.println("HookZz _malloc_zone_malloc zone=" + zone + ", size=" + size);
                return HookStatus.RET(emulator, originFunction);
            }
        });
//        emulator.attach().debug();

        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);

//        emulator.traceCode();
        hookZz.instrument(symbol, new InstrumentCallback<RegisterContext>() {
            @Override
            public void dbiCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
                System.err.println("HookZz preCall _MSGetImageByName=" + ctx.getPointerArg(0).getString(0));
            }
        });

        long start = System.currentTimeMillis();

//        emulator.traceRead();
//        emulator.attach().addBreakPoint(null, 0x401495dc);
//        emulator.traceCode();

        /*whale.inlineHookFunction(symbol, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer pointer = context.getPointerArg(0);
                System.err.println("IWhale onCall _MSGetImageByName=" + pointer.getString(0) + ", origin=" + UnicornPointer.pointer(emulator, originFunction));
                return HookStatus.RET(emulator, originFunction);
            }
        });*/

//        emulator.traceCode();
        /*whale.importHookFunction("_strcmp", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer pointer1 = context.getPointerArg(0);
                Pointer pointer2 = context.getPointerArg(1);
                System.out.println("IWhale strcmp str1=" + pointer1.getString(0) + ", str2=" + pointer2.getString(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator, originFunction);
            }
        });*/

        // emulator.attach().addBreakPoint(module, 0x00b608L);
//        emulator.traceCode();
        Number[] numbers = symbol.call(emulator, "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        long ret = numbers[0].longValue();
        System.err.println("_MSGetImageByName ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        symbol = module.findSymbolByName("_MSFindSymbol");
        assertNotNull(symbol);
        start = System.currentTimeMillis();
        // emulator.traceCode();
        numbers = symbol.call(emulator, UnidbgPointer.pointer(emulator, ret), "_MSGetImageByName");
        ret = numbers[0].longValue();
        System.err.println("_MSFindSymbol ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        HookLoader.load(emulator).hookObjcMsgSend(this);

        start = System.currentTimeMillis();
//        Logger.getLogger("com.github.unidbg.ios.MachOLoader").setLevel(Level.DEBUG);
//        Logger.getLogger("com.github.unidbg.spi.AbstractLoader").setLevel(Level.DEBUG);
//        emulator.attach(0x102984000L, 0x102998000L).addBreakPoint(null, 0x102984000L + 0x000000000000A0A4);

//        new CoreTelephony("中国电信", "460", "cn", "01", false).processHook(emulator);

        Logger.getLogger("com.github.unidbg.AbstractEmulator").setLevel(Level.INFO);
//        emulator.attach().addBreakPoint(null, 0x00000001000072E0L);
//        emulator.traceCode(0xffffe0000L, 0xffffe0000L + 0x10000);
        Logger.getLogger("com.github.unidbg.ios.ARM64SyscallHandler").setLevel(Level.INFO);
//        Module debugModule = emulator.getMemory().findModule("CoreFoundation");
//        emulator.attach().addBreakPoint(debugModule, 0x0000000000105AA4);
        Logger.getLogger("com.github.unidbg.ios.Dyld64").setLevel(Level.INFO);
        loader.getExecutableModule().callEntry(emulator);
        System.err.println("callExecutableEntry offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        emulator.getSyscallHandler().setVerbose(false);
    }

    public static void main(String[] args) throws Exception {
        Substrate64Test test = new Substrate64Test();
        test.setUp();
        test.testMS();
        test.tearDown();
    }

    @Override
    public void onMsgSend(Emulator<?> emulator, boolean systemClass, String className, String cmd, Pointer lr) {
//        System.out.printf("onMsgSend [%s %s] from %s\n", className, cmd, lr);
    }
}
