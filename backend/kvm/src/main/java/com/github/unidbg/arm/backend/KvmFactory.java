package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.kvm.Kvm;
import com.github.unidbg.arm.backend.kvm.KvmBackend32;
import com.github.unidbg.arm.backend.kvm.KvmBackend64;
import org.scijava.nativelib.NativeLibraryUtil;

import java.io.File;
import java.io.IOException;

public class KvmFactory extends BackendFactory {

    private static boolean supportKvm() {
        File kvm = new File("/dev/kvm");
        return kvm.exists();
    }

    static {
        try {
            if (NativeLibraryUtil.getArchitecture() == NativeLibraryUtil.Architecture.LINUX_ARM64 &&
                    supportKvm()) {
                org.scijava.nativelib.NativeLoader.loadLibrary("kvm");
            }
        } catch (IOException ignored) {
        }
    }

    public KvmFactory(boolean fallbackUnicorn) {
        super(fallbackUnicorn);
    }

    @Override
    protected Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit) {
        if (supportKvm()) {
            Kvm kvm = new Kvm(is64Bit);
            if (is64Bit) {
                return new KvmBackend64(emulator, kvm);
            } else {
                return new KvmBackend32(emulator, kvm);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

}
