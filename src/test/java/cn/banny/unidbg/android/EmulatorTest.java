package cn.banny.unidbg.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import junit.framework.TestCase;

public abstract class EmulatorTest extends TestCase {

    protected Emulator emulator;

    private long start;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        start = System.currentTimeMillis();
        emulator = createARMEmulator();
        emulator.getMemory().setLibraryResolver(createLibraryResolver());
    }

    protected Emulator createARMEmulator() {
        return new AndroidARMEmulator();
    }

    protected abstract LibraryResolver createLibraryResolver();

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        emulator.close();
        System.err.println("test offset=" + (System.currentTimeMillis() - start) + "ms");
    }
}
