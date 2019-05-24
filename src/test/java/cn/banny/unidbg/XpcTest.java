package cn.banny.unidbg;

import cn.banny.unidbg.arm.Arm32RegisterContext;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.substrate.ISubstrate;
import cn.banny.unidbg.hook.substrate.Substrate;
import cn.banny.unidbg.hook.whale.IWhale;
import cn.banny.unidbg.hook.whale.Whale;
import cn.banny.unidbg.ios.DarwinARMEmulator;
import cn.banny.unidbg.ios.DarwinResolver;
import cn.banny.unidbg.memory.MemoryBlock;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

import java.io.File;

public class XpcTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARMEmulator();
    }

    public void testXpcNoPie() throws Exception {
        emulator.getMemory().setCallInitFunction();
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/xpcNP"));

        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator);
        System.err.println("testXpcNoPie ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    public void testXpc() throws Exception {
//        emulator.attach().addBreakPoint(null, 0x403b7dfc);
//        emulator.traceCode();
        emulator.getMemory().setCallInitFunction();
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/xpc"));

        Symbol malloc_default_zone = module.findSymbolByName("_malloc_default_zone");
        Pointer zone = UnicornPointer.pointer(emulator, malloc_default_zone.call(emulator)[0].intValue());
        assertNotNull(zone);
        System.err.println("_malloc_default_zone zone=" + zone);

        long start = System.currentTimeMillis();
//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x0000b794);
        int ret = module.callEntry(emulator);
        System.err.println("testXpc ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x4041ba6c);
        MemoryBlock block = emulator.getMemory().malloc(1, false);
        System.out.println("block=" + block.getPointer());
//        emulator.traceCode();
//        emulator.attach().addBreakPoint(null, 0x4041ddac);
        block.free(false);

        ISubstrate substrate = Substrate.getInstance(emulator);
        assertNotNull(substrate.getImageByName("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"));
        assertNotNull(substrate.getImageByName("xpc"));
        assertNull(substrate.getImageByName("not_exists"));

        Module libSystem = substrate.getImageByName("/usr/lib/libSystem.B.dylib");
        assertNotNull(libSystem);

        IWhale whale = Whale.getInstance(emulator);
        whale.WImportHookFunction("_strcmp", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Arm32RegisterContext context = emulator.getRegisterContext();
                Pointer pointer1 = context.getR0Pointer();
                Pointer pointer2 = context.getR1Pointer();
                System.out.println("strcmp str1=" + pointer1.getString(0) + ", str2=" + pointer2.getString(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator.getUnicorn(), originFunction);
            }
        });
        assertNotNull(substrate.findSymbol(null, "_malloc"));
    }

    public static void main(String[] args) throws Exception {
        XpcTest test = new XpcTest();
        test.setUp();
        test.testXpc();
        test.tearDown();
    }

}
