package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.ArmHook;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.linux.android.URLibraryFile;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.spi.LibraryFile;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.net.URL;

public abstract class BaseHook implements IHook {

    protected final Emulator emulator;
    protected final Module module;

    public BaseHook(Emulator emulator, String libName) throws IOException {
        this.emulator = emulator;
        this.module = emulator.getMemory().load(resolveLibrary(libName));
    }

    protected Pointer createReplacePointer(final ReplaceCallback callback, final Pointer backup) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        return svcMemory.registerSvc(emulator.getPointerSize() == 4 ? new ArmHook() {
            @Override
            protected HookStatus hook(Emulator emulator) {
                return callback.onCall(emulator, backup.getInt(0) & 0xffffffffL);
            }
        } : new Arm64Hook() {
            @Override
            protected HookStatus hook(Emulator emulator) {
                return callback.onCall(emulator, backup.getLong(0));
            }
        });
    }

    private LibraryFile resolveLibrary(String libName) {
        URL url = BaseHook.class.getResource(emulator.getLibraryPath() + libName + emulator.getLibraryExtension());
        if (url == null) {
            throw new IllegalStateException("resolve library failed: " + libName);
        }

        boolean isIOS = ".dylib".equals(emulator.getLibraryExtension());
        return isIOS ? new com.github.unidbg.ios.URLibraryFile(url, libName, null) : new URLibraryFile(url, libName, -1);
    }

    @Override
    public Module getModule() {
        return module;
    }

}
