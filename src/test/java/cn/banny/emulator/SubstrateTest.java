package cn.banny.emulator;

import cn.banny.emulator.arm.HookStatus;
import cn.banny.emulator.hook.ReplaceCallback;
import cn.banny.emulator.hook.hookzz.HookZz;
import cn.banny.emulator.hook.whale.IWhale;
import cn.banny.emulator.hook.whale.Whale;
import cn.banny.emulator.ios.DarwinARMEmulator;
import cn.banny.emulator.ios.DarwinResolver;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

import java.io.File;

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
        // emulator.getMemory().setCallInitFunction();
        // emulator.attach().addBreakPoint(null, 0x40237a30);
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libsubstrate.dylib"));
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");

        IWhale whale = Whale.getInstance(emulator);
//        emulator.traceCode();
        whale.WImportHookFunction("_strcmp", "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Pointer pointer1 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer pointer2 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                System.out.println("strcmp str1=" + pointer1.getString(0) + ", str2=" + pointer2.getString(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator.getUnicorn(), originFunction);
            }
        });

        HookZz.getInstance(emulator);

        start = System.currentTimeMillis();
        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);
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
