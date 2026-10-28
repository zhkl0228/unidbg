package com.github.unidbg.linux;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import org.junit.Test;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class ImportedSymbolTest {

    private static final File LIBRARY = new File("src/test/resources/example_binaries/armeabi-v7a/libnative-lib.so");

    @Test
    public void relocatedImportsAreRecorded() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            Module module = emulator.loadLibrary(LIBRARY);

            Set<String> names = new HashSet<>();
            for (Module.ImportedSymbol symbol : module.getImportedSymbols()) {
                assertSame(symbol, module.findImportedSymbolByRelocationAddress(symbol.relocationAddress));
                names.add(symbol.symbolName);
            }
            assertFalse(names.isEmpty());
            assertTrue(names.contains("malloc"));
            assertTrue(names.contains("strlen"));
        }
    }

}
