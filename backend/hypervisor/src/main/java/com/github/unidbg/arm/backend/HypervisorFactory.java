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

    public HypervisorFactory(boolean fallbackUnicorn) {
        super(fallbackUnicorn);
    }

    @Override
    protected Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit) {
        Hypervisor hypervisor = new Hypervisor(is64Bit);
        if (is64Bit) {
            return new HypervisorBackend64(emulator, hypervisor);
        } else {
            throw new UnsupportedOperationException();
        }
    }

}
