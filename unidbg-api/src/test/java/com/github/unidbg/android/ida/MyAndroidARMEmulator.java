package com.github.unidbg.android.ida;

import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;

class MyAndroidARMEmulator extends AndroidARMEmulator {

    public MyAndroidARMEmulator(File executable) {
        super(executable.getName(), new File("target/rootfs/ida"));
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        return new MyARMSyscallHandler(svcMemory);
    }

}
