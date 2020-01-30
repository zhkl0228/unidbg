package cn.banny.unidbg.android;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.file.StdoutCallback;
import cn.banny.unidbg.memory.Memory;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class CrackMe {

    public static void main(String[] args) throws IOException {
        File executable = new File("src/test/resources/example_binaries/crackme1");
        final Emulator emulator = new AndroidARMEmulator(executable.getName());
        emulator.setWorkDir(executable.getParentFile());
        try {
            Memory memory = emulator.getMemory();
            LibraryResolver resolver = new AndroidResolver(19);
            resolver.setStdoutCallback(new StdoutCallback() {
                @Override
                public void notifyOut(byte[] data, boolean err) {
                    Inspector.inspect(data, "notifyOut data=" + new String(data, StandardCharsets.UTF_8));
                }
            });
            memory.setLibraryResolver(resolver);

            memory.setCallInitFunction();

            Module module = emulator.loadLibrary(executable);

            long start = System.currentTimeMillis();
//             emulator.traceCode(module.base, module.base + module.size);
//             emulator.attach().addBreakPoint(libc.base + 0x00038F20);
            System.out.println("exit code: " + module.callEntry(emulator, executable.getName(), "mm") + ", offset=" + (System.currentTimeMillis() - start) + "ms");
//            start = System.currentTimeMillis();
//            System.out.println("exit code: " + module.callEntry(emulator, "crackme1", "11") + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        } finally {
            IOUtils.closeQuietly(emulator);
        }
    }

}
