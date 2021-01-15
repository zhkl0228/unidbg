package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.dynarmic.Dynarmic;
import com.github.unidbg.arm.backend.hypervisor.Hypervisor;
import org.scijava.nativelib.NativeLibraryUtil;
import org.scijava.nativelib.NativeLoader;

import java.io.File;
import java.io.IOException;

public class BackendFactory {

    static {
        if (NativeLibraryUtil.getArchitecture() == NativeLibraryUtil.Architecture.OSX_ARM64) {
            try {
                String path = NativeLibraryUtil.getPlatformLibraryPath(NativeLibraryUtil.DEFAULT_SEARCH_PATH);
                File extracted = NativeLoader.getJniExtractor().extractJni(path, "jnidispatch");
                if (extracted == null) {
                    throw new IllegalStateException("extract osx arm64 libjnidispatch.jnilib failed.");
                }
                extracted.deleteOnExit();
                System.setProperty("jna.boot.library.path", extracted.getParentFile().getAbsolutePath());
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static Backend createBackend(Emulator<?> emulator, boolean is64Bit) {
        boolean useDynarmic = Dynarmic.isUseDynarmic();
        if (useDynarmic) {
            Backend backend = DynarmicBackend.tryInitialize(emulator, is64Bit);
            if (backend != null) {
                Dynarmic.onBackendInitialized();
                return backend;
            } else if (Dynarmic.isForceUseDynarmic()) {
                throw new IllegalStateException("Initialize dynarmic backend failed");
            }
        }

        boolean useHypervisor = Hypervisor.isUseHypervisor();
        if (useHypervisor) {
            Backend backend = HypervisorBackend.tryInitialize(emulator, is64Bit);
            if (backend != null) {
                Hypervisor.onBackendInitialized();
                return backend;
            } else if (Hypervisor.isForceUseHypervisor()) {
                throw new IllegalStateException("Initialize hypervisor backend failed");
            }
        }
        return new UnicornBackend(emulator, is64Bit);
    }

}
