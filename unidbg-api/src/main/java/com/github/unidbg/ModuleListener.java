package com.github.unidbg;

public interface ModuleListener {

    void onLoaded(Emulator<?> emulator, Module module);

}
