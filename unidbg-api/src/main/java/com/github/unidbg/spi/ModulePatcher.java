package com.github.unidbg.spi;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;

public abstract class ModulePatcher implements ModuleListener {

    private final String path;

    public ModulePatcher(String path) {
        this.path = path;
    }

    @Override
    public final void onLoaded(Emulator<?> emulator, Module module) {
        if (module.getPath().equals(path)) {
            if (emulator.is32Bit()) {
                patch32(emulator, module);
            } else {
                patch64(emulator, module);
            }
        }
    }

    protected abstract void patch32(Emulator<?> emulator, Module module);
    protected abstract void patch64(Emulator<?> emulator, Module module);

}
