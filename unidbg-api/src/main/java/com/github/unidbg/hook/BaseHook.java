package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Hook;
import com.github.unidbg.arm.ArmHook;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.EditableArm32RegisterContext;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.linux.android.URLibraryFile;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.spi.LibraryFile;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.Stack;

public abstract class BaseHook implements IHook {

    protected final Emulator<?> emulator;
    protected final Module module;

    public BaseHook(Emulator<?> emulator, String libName) throws IOException {
        this.emulator = emulator;
        this.module = emulator.getMemory().load(resolveLibrary(libName));
    }

    protected Pointer createReplacePointer(final ReplaceCallback callback, final Pointer backup, boolean enablePostCall) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        final Stack<Object> context = new Stack<>();
        return svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Hook(enablePostCall) {
            @Override
            protected HookStatus hook(Emulator<?> emulator) {
                context.clear();
                return callback.onCall(emulator, new Arm64HookContext(context, emulator.<EditableArm64RegisterContext>getContext()), backup.getLong(0));
            }
            @Override
            public void handleCallback(Emulator<?> emulator) {
                EditableArm64RegisterContext registerContext = emulator.getContext();
                callback.postCall(emulator, new Arm64HookContext(context, registerContext));
            }
        } : new ArmHook(enablePostCall) {
            @Override
            protected HookStatus hook(Emulator<?> emulator) {
                context.clear();
                return callback.onCall(emulator, new Arm32HookContext(context, emulator.<EditableArm32RegisterContext>getContext()), backup.getInt(0) & 0xffffffffL);
            }
            @Override
            public void handleCallback(Emulator<?> emulator) {
                EditableArm32RegisterContext registerContext = emulator.getContext();
                callback.postCall(emulator, new Arm32HookContext(context, registerContext));
            }
        });
    }

    private LibraryFile resolveLibrary(String libName) {
        URL url = BaseHook.class.getResource(emulator.getLibraryPath() + libName + emulator.getLibraryExtension());
        if (url == null) {
            throw new IllegalStateException("resolve library failed: " + libName + emulator.getLibraryExtension());
        }

        boolean isIOS = ".dylib".equals(emulator.getLibraryExtension());
        return isIOS ? new com.github.unidbg.ios.URLibraryFile(url, libName + emulator.getLibraryExtension(), null, Collections.<String>emptyList()) : new URLibraryFile(url, libName + emulator.getLibraryExtension(), -1);
    }

    protected final long numberToAddress(Number number) {
        return numberToAddress(emulator, number);
    }

    public static long numberToAddress(Emulator<?> emulator, Number number) {
        if (emulator.is64Bit()) {
            return number.longValue();
        } else {
            return number.intValue() & 0xffffffffL;
        }
    }

    @Override
    public Module getModule() {
        return module;
    }

}
