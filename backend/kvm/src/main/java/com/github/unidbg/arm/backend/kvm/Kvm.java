package com.github.unidbg.arm.backend.kvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Closeable;

public class Kvm implements Closeable {

    private static final Log log = LogFactory.getLog(Kvm.class);

    public static native int getMaxSlots();
    public static native int getPageSize();
    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long handle);

    private static native long set_user_memory_region(long handle, int slot, long guest_phys_addr, long memory_size);

    private static native long reg_read_cpacr_el1(long handle);

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

    public long set_user_memory_region(int slot, long guest_phys_addr, long memory_size) {
        long userspace_addr = set_user_memory_region(nativeHandle, slot, guest_phys_addr, memory_size);
        if (userspace_addr == 0) {
            throw new KvmException("set_user_memory_region failed: slot=" + slot + ", guest_phys_addr=0x" + Long.toHexString(guest_phys_addr) + ", memory_size=0x" + Long.toHexString(memory_size));
        }
        return userspace_addr;
    }

    public long reg_read_cpacr_el1() {
        long cpacr = reg_read_cpacr_el1(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_cpacr_el1=0x" + Long.toHexString(cpacr));
        }
        return cpacr;
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);

        singleInstance = null;
    }

}
