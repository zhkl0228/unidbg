package cn.banny.unidbg.ios;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.android.EmulatorTest;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.substrate.ISubstrate;
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

        Symbol objc_getClass = module.findSymbolByName("_objc_getClass");
        assertNotNull(objc_getClass);

        MemoryBlock block = emulator.getMemory().malloc(32, false);
        Symbol snprintf = module.findSymbolByName("_snprintf");
        snprintf.call(emulator, block.getPointer(), 32, "%llu", 0x0, 0x16d, 0x0);
        Inspector.inspect(block.getPointer().getByteArray(0, 32), "snprintf");
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
        Module cydiaSubstrate = substrate.getImageByName("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        assertNotNull(cydiaSubstrate);
        assertNotNull(substrate.getImageByName("xpc"));
        assertNull(substrate.getImageByName("not_exists"));

        Module libSystem = substrate.getImageByName("/usr/lib/libSystem.B.dylib");
        assertNotNull(libSystem);

        Symbol _MSFindSymbol = substrate.findSymbol(cydiaSubstrate, "_MSFindSymbol");
        assertNotNull(_MSFindSymbol);
        substrate.hookFunction(_MSFindSymbol, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                long image = context.getLongArg(0);
                Pointer symbol = context.getPointerArg(1);
                System.out.println("_MSFindSymbol image=0x" + Long.toHexString(image) + ", symbol=" + symbol.getString(0));
                return HookStatus.RET(emulator, originFunction);
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
