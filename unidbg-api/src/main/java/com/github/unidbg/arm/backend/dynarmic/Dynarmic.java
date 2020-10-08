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
    private static native void nativeDestroy(long handle);

    private static native int mem_map(long handle, long address, long size, int perms);

    final long nativeHandle;

    public Dynarmic(boolean is64Bit) {
        this.nativeHandle = nativeInitialize(is64Bit);
    }

    public void mem_map(long address, long size, int perms) {
        int ret = mem_map(nativeHandle, address, size, perms);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);
    }

}
