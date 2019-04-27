package cn.banny.emulator;

import cn.banny.emulator.hook.hookzz.HookZz;
import cn.banny.emulator.hook.whale.Whale;
import cn.banny.emulator.ios.DarwinARMEmulator;
import cn.banny.emulator.ios.DarwinResolver;

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
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libsubstrate.dylib"));
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");

        Whale.getInstance(emulator);
        HookZz.getInstance(emulator);

        start = System.currentTimeMillis();
        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);
        // emulator.attach().addBreakPoint(module, 0x00b608L);
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
