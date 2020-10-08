package com.github.unidbg.arm.backend.dynarmic;

import java.io.Closeable;
import java.io.IOException;

public class Dynarmic implements Closeable {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("dynarmic");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long nativeHandle);

    final long nativeHandle;

    public Dynarmic(boolean is64Bit) {
        this.nativeHandle = nativeInitialize(is64Bit);
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);
    }

}
