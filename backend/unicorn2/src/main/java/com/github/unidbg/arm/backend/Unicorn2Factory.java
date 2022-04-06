package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;

import java.io.IOException;

public class Unicorn2Factory extends BackendFactory {

    static {
        try {
            org.scijava.nativelib.NativeLoader.loadLibrary("unicorn");
        } catch (IOException ignored) {
        }
    }

    public Unicorn2Factory(boolean fallbackUnicorn) {
        super(fallbackUnicorn);
    }

    @Override
    protected Backend newBackendInternal(Emulator<?> emulator, boolean is64Bit) {
        return new Unicorn2Backend(emulator, is64Bit);
    }

}
