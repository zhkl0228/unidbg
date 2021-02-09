package com.github.unidbg.arm.backend.kvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Closeable;

public class Kvm implements Closeable {

    private static final Log log = LogFactory.getLog(Kvm.class);

    public static native int getMaxSlots();
    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long handle);

    private final long nativeHandle;

    private static Kvm singleInstance;

    public Kvm(boolean is64Bit) {
        if (singleInstance != null) {
            throw new IllegalStateException("Only one kvm VM instance per process allowed.");
        }

        this.nativeHandle = nativeInitialize(is64Bit);
        singleInstance = this;
    }

    public void setKvmCallback(KvmCallback callback) {
        if (log.isDebugEnabled()) {
            log.debug("setKvmCallback callback" + callback);
        }
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);

        singleInstance = null;
    }

}
