package com.github.unidbg.arm.backend.hypervisor;

import com.sun.jna.NativeLoader;

import java.io.IOException;

public class HypervisorLoader {

    static {
        try {
            if (NativeLoader.isAppleSilicon()) {
                org.scijava.nativelib.NativeLoader.loadLibrary("hypervisor");
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * 在创建模拟器之前调用
     */
    public static void useHypervisor() {
        useHypervisor(false);
    }

    private static void useHypervisor(boolean force) {
        if (force && !NativeLoader.isAppleSilicon()) {
            throw new IllegalStateException("NOT apple silicon.");
        }

        System.setProperty(Hypervisor.USE_HYPERVISOR_BACKEND_KEY, "true");
        System.setProperty(Hypervisor.FORCE_USE_HYPERVISOR_KEY, Boolean.toString(force));
    }

    /**
     * 在创建模拟器之前调用
     */
    public static void forceUseHypervisor() {
        useHypervisor(true);
    }

}
