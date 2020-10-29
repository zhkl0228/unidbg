package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.dynarmic.Dynarmic;

public class BackendFactory {

    public static Backend createBackend(Emulator<?> emulator, boolean is64Bit) {
        boolean useDynarmic = Dynarmic.isUseDynarmic();
        if (useDynarmic) {
            Backend backend = DynarmicBackend.tryInitialize(emulator, is64Bit);
            if (backend != null) {
                return backend;
            }
        }
        return new UnicornBackend(is64Bit);
    }

}
