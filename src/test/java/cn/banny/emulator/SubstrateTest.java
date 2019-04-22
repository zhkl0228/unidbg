package cn.banny.emulator;

import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.ios.DarwinARMEmulator;
import cn.banny.emulator.ios.DarwinResolver;
import unicorn.Unicorn;

import java.io.File;

public class SubstrateTest extends EmulatorTest {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected Emulator createARMEmulator() {
        return new DarwinARMEmulator();
    }

    public void testMS() throws Exception {
        long start = System.currentTimeMillis();
        emulator.getMemory().setCallInitFunction();
        Unicorn unicorn = emulator.getUnicorn();
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libsubstrate.dylib"));
        System.err.println("load offset=" + (System.currentTimeMillis() - start) + "ms");
        start = System.currentTimeMillis();
        // emulator.traceCode();
        Symbol symbol = module.findSymbolByName("MSGetImageByName");
        Number[] numbers = symbol.call(emulator, "/system/lib/libc.so");
        long address = numbers[0].intValue() & 0xffffffffL;
        System.out.println("ret=" + ARM.readCString(unicorn, address));
        System.err.println("eFunc offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
