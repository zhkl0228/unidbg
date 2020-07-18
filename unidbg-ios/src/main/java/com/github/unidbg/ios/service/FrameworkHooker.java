package com.github.unidbg.ios.service;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.memory.Memory;

public abstract class FrameworkHooker {

    private final String moduleName;

    public FrameworkHooker() {
        this(null);
    }

    public FrameworkHooker(String moduleName) {
        this.moduleName = moduleName;
    }

    public final void processHook(Emulator<?> emulator) {
        Memory memory = emulator.getMemory();
        String moduleName = this.moduleName == null ? getClass().getSimpleName() : this.moduleName;
        Module module = memory.findModule(moduleName);
        if (module == null) {
            throw new IllegalStateException("Find module failed: " + moduleName);
        }
        doHook(emulator, module);
    }

    protected abstract void doHook(Emulator<?> emulator, Module module);

}
