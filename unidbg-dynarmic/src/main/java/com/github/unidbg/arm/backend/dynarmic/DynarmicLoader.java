package com.github.unidbg.arm.backend.dynarmic;

import java.io.IOException;

public class DynarmicLoader {

    public static void useDynarmic() {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("dynarmic");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        System.setProperty("use.dynarmic.backend", "true");
    }

}
