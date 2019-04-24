package cn.banny.emulator;

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
        emulator.getMemory().setCallInitFunction();
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libsubstrate.dylib"));
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        start = System.currentTimeMillis();
        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);
        emulator.traceCode();
        // emulator.attach().addBreakPoint(module, 0x00b608L);
        Number[] numbers = symbol.call(emulator, "CydiaSubstrate");
        long ret = numbers[0].intValue() & 0xffffffffL;
        System.err.println("eFunc ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    public static void main(String[] args) throws Exception {
        SubstrateTest test = new SubstrateTest();
        test.setUp();
        test.testMS();
        test.tearDown();
    }

}
