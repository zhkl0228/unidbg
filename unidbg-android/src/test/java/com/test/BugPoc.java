package com.test;

import com.github.unidbg.*;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import java.io.File;

public class BugPoc {
    private static AndroidEmulator emulator;
    private static VM vm;

    public static void poc()
    {
        Backend backend = BugPoc.emulator.getBackend();
        backend.mem_map(0x20f000, 0x101000, 0);
        backend.mem_protect(0x20f000, 0x2000, 3);
        backend.mem_unmap(0x20f000, 0x101000);
    }

    public static void main(String[] args)
    {
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .setProcessName("test")
                .setRootDir(new File("unidbg-android/src/test/resources/VFS"))
                .build();

//        Memory memory = emulator.getMemory();
//        memory.setLibraryResolver(new AndroidResolver(26));
//        vm = emulator.createDalvikVM();
//        vm.setVerbose(true);
//        vm.loadLibrary(new File("unidbg-master\\unidbg-android\\target\\classes\\android\\sdk23\\lib64\\libc.so"),false);

        Backend backend = emulator.getBackend();
//        backend.mem_map(0x40000000, 0x100000, 5);
//        backend.mem_map(0x400d0000, 0x20000, 3);
//        backend.mem_map(0x400f0000, 0x10000, 5);
        backend.mem_map(0, 0x100000, 0);

        backend.mem_protect(0, 0x2000, 3);


//        backend.mem_map(0x20f000, 0x101000, 0);
//        backend.mem_protect(0x20f000, 0x2000, 3);
    }
}
