package cn.banny.unidbg.hook;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.Arm64Hook;
import cn.banny.unidbg.arm.ArmHook;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.linux.android.URLibraryFile;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.spi.LibraryFile;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.IOException;
import java.net.URL;

public abstract class BaseHook {

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
            protected HookStatus hook(Unicorn u, Emulator emulator) {
                return callback.onCall(emulator, backup.getInt(0) & 0xffffffffL);
            }
        } : new Arm64Hook() {
            @Override
            protected HookStatus hook(Unicorn u, Emulator emulator) {
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
        return isIOS ? new cn.banny.unidbg.ios.URLibraryFile(url, libName, null) : new URLibraryFile(url, libName, -1);
    }

    public Module getModule() {
        return module;
    }

}
