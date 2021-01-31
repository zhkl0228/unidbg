package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.sun.jna.NativeLoader;

import java.util.Collection;

public abstract class BackendFactory {

    static {
        NativeLoader.loadAppleSilicon();
    }

    private final boolean fallbackUnicorn;

    protected BackendFactory(boolean fallbackUnicorn) {
        this.fallbackUnicorn = fallbackUnicorn;
    }

    private Backend newBackend(Emulator<?> emulator, boolean is64Bit) {
        try {
            return newBackendInternal(emulator, is64Bit);
        } catch (Throwable e) {
            if (fallbackUnicorn) {
                return null;
            } else {
                throw e;
            }
        }
    }

    protected abstract Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit);

    public static Backend createBackend(Emulator<?> emulator, boolean is64Bit, Collection<BackendFactory> backendFactories) {
        if (backendFactories != null) {
            for (BackendFactory factory : backendFactories) {
                Backend backend = factory.newBackend(emulator, is64Bit);
                if (backend != null) {
                    return backend;
                }
            }
        }
        return new UnicornBackend(emulator, is64Bit);
    }

}
