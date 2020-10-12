package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;

public class BackendFactory {

    public static Backend createBackend(Emulator<?> emulator, boolean is64Bit) {
        boolean useDynarmic = Boolean.parseBoolean(System.getProperty("use.dynarmic.backend"));
        if (useDynarmic) {
            Backend backend = DynarmicBackend.tryInitialize(emulator, is64Bit);
            if (backend != null) {
                return backend;
            }
        }
        return new UnicornBackend(is64Bit);
    }

}
