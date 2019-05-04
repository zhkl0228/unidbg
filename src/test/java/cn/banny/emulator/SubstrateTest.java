package cn.banny.emulator;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.arm.HookStatus;
import cn.banny.emulator.hook.ReplaceCallback;
import cn.banny.emulator.hook.hookzz.*;
import cn.banny.emulator.hook.whale.IWhale;
import cn.banny.emulator.hook.whale.Whale;
import cn.banny.emulator.ios.DarwinARMEmulator;
import cn.banny.emulator.ios.DarwinResolver;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import junit.framework.AssertionFailedError;
import unicorn.ArmConst;

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
        // emulator.attach().addBreakPoint(null, 0x40237a30);
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libsubstrate.dylib"));
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");

        IWhale whale = Whale.getInstance(emulator);

        UnicornPointer memoryBlock = emulator.getMemory().malloc(0x40, false).getPointer();
        Symbol _snprintf = module.findSymbolByName("_snprintf", true);
        assertNotNull(_snprintf);

        byte[] before = memoryBlock.getByteArray(0, 0x40);
        Inspector.inspect(before, "Before memoryBlock=" + memoryBlock);
//        emulator.traceCode();
//        emulator.traceWrite(memoryBlock.peer, memoryBlock.peer + 0x40);
//        emulator.traceWrite();
        String fmt = "Test snprintf=%p\n";
//        emulator.traceRead(0xbffff9b8L, 0xbffff9b8L + fmt.length() + 1);
//        emulator.attach().addBreakPoint(null, 0x401622c2);
        _snprintf.call(emulator, memoryBlock, 0x40, fmt, memoryBlock);
        byte[] after = memoryBlock.getByteArray(0, 0x40);
        Inspector.inspect(after, "After");
        if (Arrays.equals(before, after)) {
            throw new AssertionFailedError();
        }

        start = System.currentTimeMillis();
        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);

//        emulator.traceRead();
//        emulator.attach().addBreakPoint(null, 0x401495dc);
        IHookZz hookZz = HookZz.getInstance(emulator);

        /*whale.WImportHookFunction("_malloc", "libhookzz.dylib", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                int size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
                System.out.println("malloc size=" + size);
                return HookStatus.RET(unicorn, originFunction);
            }
        });*/

        /*whale.WInlineHookFunction(symbol, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                System.err.println("preCall _MSGetImageByName=" + pointer.getString(0));
                return HookStatus.RET(unicorn, originFunction);
            }
        });*/

        whale.WImportHookFunction("_strcmp", "CydiaSubstrate", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Pointer pointer1 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer pointer2 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                System.out.println("strcmp str1=" + pointer1.getString(0) + ", str2=" + pointer2.getString(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator.getUnicorn(), originFunction);
            }
        });

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
