package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;

import org.scijava.nativelib.NativeLibraryUtil;
import org.scijava.nativelib.NativeLoader;

public class Unicorn2Factory extends BackendFactory {

    static {
        NativeLibraryUtil.loadNativeLibrary(NativeLoader.getJniExtractor(), "unicorn");
    }

    public Unicorn2Factory(boolean fallbackUnicorn) {
        super(fallbackUnicorn);
    }

    @Override
    protected Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit) {
        return new Unicorn2Backend(emulator, is64Bit);
    }

}
