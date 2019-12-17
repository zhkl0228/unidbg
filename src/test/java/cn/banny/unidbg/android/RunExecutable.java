package cn.banny.unidbg.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.ModuleListener;
import cn.banny.unidbg.unix.UnixEmulator;
import cn.banny.unidbg.linux.LinuxModule;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ElfSymbol;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;

class RunExecutable {

    static void run(File executable, ModuleListener listener, String[] preloads, Object...args) throws IOException {
        final Emulator emulator = new AndroidARMEmulator(executable.getName());
        emulator.setWorkDir(executable.getParentFile());
        try {
            long start = System.currentTimeMillis();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            memory.setCallInitFunction();
            if (listener != null) {
                memory.setModuleListener(listener);
            }
            if (preloads != null) {
                for (String preload : preloads) {
                    if (preload != null) {
                        Module preloaded = memory.dlopen(preload);
                        System.out.println("preloaded=" + preloaded);
                    }
                }
            }

            LinuxModule module = (LinuxModule) emulator.loadLibrary(executable);
            LinuxModule libc = (LinuxModule) module.getDependencyModule("libc");
            ElfSymbol environ = libc.getELFSymbolByName("environ");
            if (environ != null) {
                Pointer pointer = UnicornPointer.pointer(emulator, libc.base + environ.value);
                assert pointer != null;
                System.err.println("environ=" + pointer + ", value=" + pointer.getPointer(0));
            }
            Number __errno = libc.callFunction(emulator, "__errno")[0];
            Pointer pointer = UnicornPointer.pointer(emulator, __errno.intValue() & 0xffffffffL);
            assert pointer != null;
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            int value = pointer.getInt(0);
            assert value == UnixEmulator.EACCES;

//             emulator.traceCode();
            Pointer strerror = UnicornPointer.pointer(emulator, libc.callFunction(emulator, "strerror", UnixEmulator.ECONNREFUSED)[0].intValue() & 0xffffffffL);
            assert strerror != null;
            System.out.println(strerror.getString(0));

//             emulator.traceCode();
//             emulator.attach().addBreakPoint(libc.base + 0x00038F20);
            System.out.println("exit code: " + module.callEntry(emulator, args) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        } finally {
            IOUtils.closeQuietly(emulator);
        }
    }

    static void run(File executable, ModuleListener listener, Object...args) throws IOException {
        run(executable, listener, null, args);
    }

}
