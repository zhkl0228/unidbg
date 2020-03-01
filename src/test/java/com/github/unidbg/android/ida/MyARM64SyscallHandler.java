package com.github.unidbg.android.ida;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.memory.SvcMemory;

class MyARM64SyscallHandler extends ARM64SyscallHandler {

    public MyARM64SyscallHandler(SvcMemory svcMemory) {
        super(svcMemory);
    }

    @Override
    protected int fork(Emulator<?> emulator) {
        return emulator.getPid();
    }

}
