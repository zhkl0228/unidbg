package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.arm.backend.dynarmic.DynarmicException;
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
            throw new DynarmicException("ret=" + ret);
        }
    }

}
