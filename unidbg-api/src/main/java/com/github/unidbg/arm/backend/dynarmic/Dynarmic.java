package com.github.unidbg.arm.backend.dynarmic;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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

    private static final Log log = LogFactory.getLog(Dynarmic.class);

    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long handle);

    private static native int mem_unmap(long handle, long address, long size);
    private static native int mem_map(long handle, long address, long size, int perms);
    private static native int mem_protect(long handle, long address, long size, int perms);

    private final long nativeHandle;

    public Dynarmic(boolean is64Bit) {
        this.nativeHandle = nativeInitialize(is64Bit);
    }

    public void mem_unmap(long address, long size) {
        if (log.isDebugEnabled()) {
            log.debug("mem_unmap address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size));
        }
        int ret = mem_unmap(nativeHandle, address, size);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void mem_map(long address, long size, int perms) {
        if (log.isDebugEnabled()) {
            log.debug("mem_map address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", perms=0b" + Integer.toBinaryString(perms));
        }
        int ret = mem_map(nativeHandle, address, size, perms);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void mem_protect(long address, long size, int perms) {
        if (log.isDebugEnabled()) {
            log.debug("mem_protect address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", perms=0b" + Integer.toBinaryString(perms));
        }
        int ret = mem_protect(nativeHandle, address, size, perms);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);
    }

}
