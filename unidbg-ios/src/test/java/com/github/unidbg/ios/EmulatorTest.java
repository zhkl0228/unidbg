package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import junit.framework.TestCase;

public abstract class EmulatorTest<T extends Emulator<?>> extends TestCase {

    protected T emulator;

    private long start;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        start = System.currentTimeMillis();
        emulator = createARMEmulator();
        emulator.getMemory().setLibraryResolver(createLibraryResolver());
        emulator.getSyscallHandler().setVerbose(true);
    }

    protected abstract T createARMEmulator();

    protected abstract LibraryResolver createLibraryResolver();

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        emulator.close();
        System.err.println("test offset=" + (System.currentTimeMillis() - start) + "ms");
    }
}
