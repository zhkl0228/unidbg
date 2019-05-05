package cn.banny.emulator;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.arm.HookStatus;
import cn.banny.emulator.hook.ReplaceCallback;
import cn.banny.emulator.hook.hookzz.*;
import cn.banny.emulator.hook.whale.IWhale;
import cn.banny.emulator.hook.whale.Whale;
import cn.banny.emulator.ios.DarwinARMEmulator;
import cn.banny.emulator.ios.DarwinResolver;
import cn.banny.emulator.ios.MachO;
import cn.banny.emulator.ios.MachOModule;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import junit.framework.AssertionFailedError;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.File;
import java.util.Arrays;

public class SubstrateTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver("7.1");
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARMEmulator();
    }

    public void testMS() throws Exception {
        long start = System.currentTimeMillis();
        emulator.getMemory().setCallInitFunction();
//        emulator.attach().addBreakPoint(null, 0x401D4C0C);
//        emulator.traceCode();
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libsubstrate.dylib"));

        Pointer thread = UnicornPointer.pointer(emulator, 0xbffffbb4L);
        assertNotNull(thread);
        Inspector.inspect(thread.getByteArray(0, 16), "load offset=" + (System.currentTimeMillis() - start) + "ms, thread=" + thread);

//        Logger.getLogger("cn.banny.emulator.ios.ARM32SyscallHandler").setLevel(Level.DEBUG);

        IWhale whale = Whale.getInstance(emulator);
        /*whale.WImportHookFunction("_malloc", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                int size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                System.err.println("IWhale hook _malloc size=" + size);
                return HookStatus.RET(unicorn, originFunction);
            }
        });*/

//        emulator.attach().addBreakPoint(null, 0x40232a6c);

        Symbol malloc_num_zones = module.findSymbolByName("_malloc_num_zones");
        assertNotNull(malloc_num_zones);
        System.out.println("malloc_num_zones=" + malloc_num_zones.createPointer(emulator).getInt(0));
        Symbol malloc_default_zone = module.findSymbolByName("_malloc_default_zone");
        Symbol malloc_size = module.findSymbolByName("_malloc_size");
        Symbol free = module.findSymbolByName("_free");
        assertNotNull(malloc_default_zone);
        Pointer zone = UnicornPointer.pointer(emulator, malloc_default_zone.call(emulator)[0].intValue());
        assertNotNull(zone);
        Pointer malloc = zone.getPointer(0xc);
        Pointer block = UnicornPointer.pointer(emulator, MachOModule.emulateFunction(emulator, ((UnicornPointer) malloc).peer, zone, 0x80)[0].intValue());
        assertNotNull(block);
        Pointer sizeFun = zone.getPointer(0x8);
        int size = MachOModule.emulateFunction(emulator, ((UnicornPointer) sizeFun).peer, zone, block)[0].intValue();
        int mSize = malloc_size.call(emulator, block)[0].intValue();
        System.out.println("malloc_num_zones=" + malloc_num_zones.createPointer(emulator).getInt(0) + ", version=" + zone.getInt(0x34) + ", free_definite_size=" + zone.getPointer(0x3c));

        System.err.println("malloc_default_zone=" + malloc_default_zone + ", zone=" + zone + ", malloc=" + malloc +
                ", sizeFun=" + sizeFun + ", block=" + block + ", size=" + size + ", mSize=" + mSize);

        Logger.getLogger("cn.banny.emulator.AbstractEmulator").setLevel(Level.DEBUG);
        free.call(emulator, block);

        IHookZz hookZz = HookZz.getInstance(emulator);
        Symbol malloc_zone_malloc = module.findSymbolByName("_malloc_zone_malloc");
//        emulator.traceCode();
        hookZz.replace(malloc_zone_malloc, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer zone = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                int size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                System.err.println("_malloc_zone_malloc zone=" + zone + ", size=" + size);
                return HookStatus.RET(unicorn, originFunction);
            }
        });

        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);

//        emulator.traceCode();
        hookZz.wrap(symbol, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                System.err.println("preCall _MSGetImageByName=" + ctx.getR0Pointer().getString(0));
            }
            @Override
            public void postCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                super.postCall(emulator, ctx, info);
                System.err.println("postCall _MSGetImageByName ret=0x" + Long.toHexString(ctx.getR0()));
            }
        });

//        emulator.attach().addBreakPoint(null, 0x40235d2a);
//        emulator.traceCode();

        MemoryBlock memoryBlock = emulator.getMemory().malloc(MachO.LARGE_THRESHOLD + 1, false);
        UnicornPointer memory = memoryBlock.getPointer();
        Symbol _snprintf = module.findSymbolByName("_snprintf", true);
        assertNotNull(_snprintf);

        byte[] before = memory.getByteArray(0, 0x40);
        Inspector.inspect(before, "Before memory=" + memory);
//        emulator.traceCode();
//        emulator.traceWrite(memory.peer, memory.peer + 0x40);
//        emulator.traceWrite();
        String fmt = "Test snprintf=%p\n";
//        emulator.traceRead(0xbffff9b8L, 0xbffff9b8L + fmt.length() + 1);
//        emulator.attach().addBreakPoint(null, 0x401622c2);
        _snprintf.call(emulator, memory, 0x40, fmt, memory);
        byte[] after = memory.getByteArray(0, 0x40);
        Inspector.inspect(after, "After");
        if (Arrays.equals(before, after)) {
            throw new AssertionFailedError();
        }
//        emulator.attach().addBreakPoint(null, 0x40234c1e);
        memoryBlock.free(false);

        start = System.currentTimeMillis();

//        emulator.traceRead();
//        emulator.attach().addBreakPoint(null, 0x401495dc);
//        emulator.traceCode();

        /*whale.WInlineHookFunction(symbol, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                System.err.println("onCall _MSGetImageByName=" + pointer.getString(0) + ", origin=" + UnicornPointer.pointer(emulator, originFunction));
                return HookStatus.RET(unicorn, originFunction);
            }
        });*/

        whale.WImportHookFunction("_strcmp", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Pointer pointer1 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer pointer2 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                System.out.println("strcmp str1=" + pointer1.getString(0) + ", str2=" + pointer2.getString(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator.getUnicorn(), originFunction);
            }
        });

        // emulator.attach().addBreakPoint(module, 0x00b608L);
//        emulator.traceCode();
        Number[] numbers = symbol.call(emulator, "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        long ret = numbers[0].intValue() & 0xffffffffL;
        System.err.println("_MSGetImageByName ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        symbol = module.findSymbolByName("_MSFindSymbol");
        assertNotNull(symbol);
        start = System.currentTimeMillis();
        // emulator.traceCode();
        numbers = symbol.call(emulator, ret, "_MSGetImageByName");
        ret = numbers[0].intValue() & 0xffffffffL;
        System.err.println("_MSFindSymbol ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    public static void main(String[] args) throws Exception {
        SubstrateTest test = new SubstrateTest();
        test.setUp();
        test.testMS();
        test.tearDown();
    }

}
