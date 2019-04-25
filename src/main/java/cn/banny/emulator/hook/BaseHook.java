package cn.banny.emulator.hook;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.arm.Arm64Hook;
import cn.banny.emulator.arm.ArmHook;
import cn.banny.emulator.arm.HookStatus;
import cn.banny.emulator.linux.android.URLibraryFile;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.spi.LibraryFile;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.net.URL;

public abstract class BaseHook {

    protected final Emulator emulator;

    public BaseHook(Emulator emulator) {
        this.emulator = emulator;
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

    protected static LibraryFile resolveLibrary(Emulator emulator, String libName) {
        URL url = BaseHook.class.getResource(emulator.getLibraryPath() + libName + emulator.getLibraryExtension());
        if (url == null) {
            throw new IllegalStateException("resolve library failed: " + libName);
        }

        boolean isIOS = ".dylib".equals(emulator.getLibraryExtension());
        return isIOS ? new cn.banny.emulator.ios.URLibraryFile(url, libName, null) : new URLibraryFile(url, libName, -1);
    }

}
