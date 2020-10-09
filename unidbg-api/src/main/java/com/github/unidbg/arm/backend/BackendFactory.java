package com.github.unidbg.arm.backend;

import unicorn.Unicorn;
import unicorn.UnicornConst;

public class BackendFactory {

    public static Backend createBackend(boolean is64Bit) {
        boolean useDynarmic = Boolean.parseBoolean(System.getProperty("use.dynarmic.backend"));
        if (useDynarmic) {
            Backend backend = DynarmicBackend.tryInitialize(is64Bit);
            if (backend != null) {
                return backend;
            }
        }
        Unicorn unicorn = new Unicorn(is64Bit ? UnicornConst.UC_ARCH_ARM64 : UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM);
        return new UnicornBackend(unicorn);
    }

}
