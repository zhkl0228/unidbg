package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.hypervisor.Hypervisor;
import com.github.unidbg.arm.backend.hypervisor.HypervisorBackend64;
import org.scijava.nativelib.NativeLoader;

import java.io.IOException;

public class HypervisorFactory extends BackendFactory {

    static {
        try {
            NativeLoader.loadLibrary("hypervisor");
        } catch (IOException ignored) {
        }
    }

    public static native void testVcpu();
    public static native int getPageSize();
    public static native int getMaxVcpuCount();
    public static native int sysctlInt(String name);
    public static native long context_alloc();
    public static native void free(long context);

    public HypervisorFactory(boolean fallbackUnicorn) {
        super(fallbackUnicorn);
    }

    @Override
    protected Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit) {
        Hypervisor hypervisor = new Hypervisor(is64Bit);
        return new HypervisorBackend64(emulator, hypervisor);
    }

}
