package com.github.unidbg.arm.backend.hypervisor;

import java.io.IOException;

public class HypervisorLoader {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("hypervisor");
        } catch (IOException ignored) {
        }
    }

    public static void useHypervisor() {
        useHypervisor(false);
    }

    private static void useHypervisor(boolean force) {
        System.setProperty(Hypervisor.USE_HYPERVISOR_BACKEND_KEY, "true");
        System.setProperty(Hypervisor.FORCE_USE_HYPERVISOR_KEY, Boolean.toString(force));
    }

    public static void forceUseHypervisor() {
        useHypervisor(true);
    }

}
