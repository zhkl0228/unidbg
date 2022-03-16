package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class JToolTest {

    public static void main(String[] args) throws IOException {
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
        builder.addBackendFactory(new HypervisorFactory(true));
        Emulator<DarwinFileIO> emulator = builder.build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        emulator.getSyscallHandler().setVerbose(false);

        final File jtool = new File("unidbg-ios/src/test/resources/example_binaries/jtool_osx");
        IOResolver<DarwinFileIO> resolver = new IOResolver<DarwinFileIO>() {
            @Override
            public FileResult<DarwinFileIO> resolve(Emulator<DarwinFileIO> emulator, String pathname, int oflags) {
                if ("test_executable".equals(pathname)) {
                    return FileResult.<DarwinFileIO>success(new SimpleFileIO(oflags, jtool, pathname));
                }
                return null;
            }
        };
        emulator.getSyscallHandler().addIOResolver(resolver);

        Module module = emulator.loadLibrary(jtool);
        long start = System.currentTimeMillis();
        int ret = module.callEntry(emulator, "-v", "-l", "--sig", "test_executable");
        System.err.println("jtool backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
