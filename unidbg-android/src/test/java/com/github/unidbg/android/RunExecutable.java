package com.github.unidbg.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.linux.LinuxModule;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.UnixEmulator;
import com.sun.jna.Pointer;
import net.fornwall.jelf.ElfSymbol;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;

class RunExecutable {

    static void run(File executable, ModuleListener listener, String[] preloads, String...args) throws IOException {
        final Emulator<?> emulator = AndroidEmulatorBuilder.for32Bit()
                .setProcessName(executable.getName())
                .setRootDir(new File("target/rootfs"))
                .build();
        try {
            long start = System.currentTimeMillis();
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));

            if (listener != null) {
                memory.addModuleListener(listener);
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
                Pointer pointer = UnidbgPointer.pointer(emulator, libc.base + environ.value);
                assert pointer != null;
                System.err.println("environ=" + pointer + ", value=" + pointer.getPointer(0));
            }
            Number __errno = libc.callFunction(emulator, "__errno")[0];
            Pointer pointer = UnidbgPointer.pointer(emulator, __errno.intValue() & 0xffffffffL);
            assert pointer != null;
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            int value = pointer.getInt(0);
            assert value == UnixEmulator.EACCES;

//             emulator.traceCode();
            Pointer strerror = UnidbgPointer.pointer(emulator, libc.callFunction(emulator, "strerror", UnixEmulator.ECONNREFUSED)[0].intValue() & 0xffffffffL);
            assert strerror != null;
            System.out.println(strerror.getString(0));

//             emulator.traceCode();
//             emulator.attach().addBreakPoint(libc.base + 0x00038F20);
            System.out.println("exit code: " + module.callEntry(emulator, args) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        } finally {
            IOUtils.closeQuietly(emulator);
        }
    }

    static void run(File executable, ModuleListener listener, String...args) throws IOException {
        run(executable, listener, null, args);
    }

}
