package com.github.unidbg.android.ida;

import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;
import java.util.Collections;

class MyAndroidARMEmulator extends AndroidARMEmulator {

    public MyAndroidARMEmulator(File executable) {
        super(executable.getName(),
                new File("target/rootfs/ida"),
                Collections.<BackendFactory>singleton(new DynarmicFactory(true)));
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new MyARMSyscallHandler(svcMemory);
    }

}
