package com.github.unidbg.android.ida;

import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;
import java.util.Collections;

class MyAndroidARM64Emulator extends AndroidARM64Emulator {

    public MyAndroidARM64Emulator(File executable) {
        super(executable.getName(),
                new File("target/rootfs/ida"),
                Collections.<BackendFactory>singleton(new HypervisorFactory(true)));
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new MyARM64SyscallHandler(svcMemory);
    }

}
