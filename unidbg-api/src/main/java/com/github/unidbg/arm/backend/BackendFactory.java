package com.github.unidbg.arm.backend;

public class BackendFactory {

    public static Backend createBackend(boolean is64Bit) {
        boolean useDynarmic = Boolean.parseBoolean(System.getProperty("use.dynarmic.backend"));
        if (useDynarmic) {
            Backend backend = DynarmicBackend.tryInitialize(is64Bit);
            if (backend != null) {
                return backend;
            }
        }
        return new UnicornBackend(is64Bit);
    }

}
