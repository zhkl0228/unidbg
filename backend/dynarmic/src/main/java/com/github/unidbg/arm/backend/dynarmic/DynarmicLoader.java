package com.github.unidbg.arm.backend.dynarmic;

import java.io.IOException;

public class DynarmicLoader {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("dynarmic");
        } catch (IOException ignored) {
        }
    }

    /**
     * 在创建模拟器之前调用
     */
    public static void useDynarmic() {
        useDynarmic(false);
    }

    private static void useDynarmic(boolean force) {
        System.setProperty(Dynarmic.USE_DYNARMIC_BACKEND_KEY, "true");
        System.setProperty(Dynarmic.FORCE_USE_DYNARMIC_KEY, Boolean.toString(force));
    }

    /**
     * 在创建模拟器之前调用
     */
    public static void forceUseDynarmic() {
        useDynarmic(true);
    }

}
