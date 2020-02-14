package com.github.unidbg.ios.service;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.memory.Memory;

public abstract class ServiceHook {

    protected final Emulator emulator;
    protected final Memory memory;
    protected final Module module;

    public ServiceHook(Emulator emulator, String moduleName) {
        this.emulator = emulator;
        this.memory = emulator.getMemory();
        this.module = memory.findModule(moduleName);
        if (this.module == null) {
            throw new IllegalStateException("Find module failed: " + moduleName);
        }
    }

    public abstract void tryHook();

}
