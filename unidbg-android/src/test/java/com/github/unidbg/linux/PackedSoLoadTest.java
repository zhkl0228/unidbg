package com.github.unidbg.linux;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 段偏移越过文件末尾的 SO 等价于加壳/损坏样本。
 */
public class PackedSoLoadTest {

    private static final File LIBRARY = new File("src/test/resources/example_binaries/armeabi-v7a/libnative-lib.so");

    @Test
    public void truncatedLibraryStillLoads() throws Exception {
        byte[] data = Files.readAllBytes(LIBRARY.toPath());
        File truncated = File.createTempFile("truncated", ".so");
        try {
            Files.write(truncated.toPath(), Arrays.copyOf(data, data.length * 6 / 10));

            try (AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit().addBackendFactory(new Unicorn2Factory(true)).build()) {
                Memory memory = emulator.getMemory();
                memory.setLibraryResolver(new AndroidResolver(23));

                Module module = emulator.loadLibrary(truncated);

                assertNotNull(module);
                assertTrue(module.name.endsWith(".so"));
                assertTrue(module.getImportedSymbols().isEmpty());
                assertTrue(module.getNeededLibraries().isEmpty());
            }
        } finally {
            truncated.delete();
        }
    }

}
