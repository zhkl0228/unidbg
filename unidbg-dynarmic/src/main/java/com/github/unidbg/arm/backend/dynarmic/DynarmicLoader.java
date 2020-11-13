package com.github.unidbg.arm.backend.dynarmic;

import java.io.IOException;

public class DynarmicLoader {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("dynarmic");
        } catch (IOException ignored) {
        }
    }

    public static void useDynarmic() {
        useDynarmic(false);
    }

    private static void useDynarmic(boolean force) {
        System.setProperty(Dynarmic.USE_DYNARMIC_BACKEND_KEY, "true");
        System.setProperty(Dynarmic.FORCE_USE_DYNARMIC_KEY, Boolean.toString(force));
    }

    public static void forceUseDynarmic() {
        useDynarmic(true);
    }

}
