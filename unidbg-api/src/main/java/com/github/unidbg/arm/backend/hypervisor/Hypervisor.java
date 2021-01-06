package com.github.unidbg.arm.backend.hypervisor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Hypervisor {

    private static final Log log = LogFactory.getLog(Hypervisor.class);

    static final String USE_HYPERVISOR_BACKEND_KEY = "use.hypervisor.backend";
    static final String FORCE_USE_HYPERVISOR_KEY = "force.use.hypervisor";

    public static boolean isUseHypervisor() {
        return Boolean.parseBoolean(System.getProperty(USE_HYPERVISOR_BACKEND_KEY));
    }

    public static void onBackendInitialized() {
        System.setProperty(USE_HYPERVISOR_BACKEND_KEY, "false");
    }

    public static boolean isForceUseHypervisor() {
        return Boolean.parseBoolean(System.getProperty(FORCE_USE_HYPERVISOR_KEY));
    }

    private static native int setHypervisorCallback(long handle, HypervisorCallback callback);

    private static native long createVM(boolean is64Bit);

    private static native int mem_unmap(long handle, long address, long size);
    private static native int mem_map(long handle, long address, long size, int perms);
    private static native int mem_protect(long handle, long address, long size, int perms);

    private final long nativeHandle;

    public Hypervisor(boolean is64Bit) {
        this.nativeHandle = createVM(is64Bit);
    }

    public void setHypervisorCallback(HypervisorCallback callback) {
        if (log.isDebugEnabled()) {
            log.debug("setHypervisorCallback callback" + callback);
        }

        int ret = setHypervisorCallback(nativeHandle, callback);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void mem_map(long address, long size, int perms) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_map(nativeHandle, address, size, perms);
        if (log.isDebugEnabled()) {
            log.debug("mem_map address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", perms=0b" + Integer.toBinaryString(perms) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

}
