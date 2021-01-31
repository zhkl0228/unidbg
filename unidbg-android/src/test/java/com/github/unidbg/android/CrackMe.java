package com.github.unidbg.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.XHookImpl;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import unicorn.ArmConst;

import java.io.File;
import java.io.IOException;

public class CrackMe {

    public static void main(String[] args) throws IOException {
        new CrackMe().crack();
    }

    private final Emulator<?> emulator;
    private final Module module;
    private final File executable;

    public CrackMe() {
        executable = new File("unidbg-android/src/test/resources/example_binaries/crackme1");
        emulator = AndroidEmulatorBuilder.for32Bit()
                .setProcessName(executable.getName())
                .setRootDir(new File("target/rootfs"))
                .addBackendFactory(new DynarmicFactory(true))
                .build();
        Memory memory = emulator.getMemory();
        LibraryResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        module = emulator.loadLibrary(executable);
    }

    private boolean canStop;

    private void crack() {
        IxHook ixHook = XHookImpl.getInstance(emulator);
        ixHook.register(executable.getName(), "strlen", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                String str = emulator.getContext().getPointerArg(0).getString(0);
                System.err.printf("strlen[\"%s\"] called from %s%n", str, UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                return HookStatus.RET(emulator, originFunction);
            }
        });
        ixHook.register(executable.getName(), "puts", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                String str = emulator.getContext().getPointerArg(0).getString(0);
                System.err.printf("puts[\"%s\"] called from %s%n", str, UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                if (str.startsWith("yes")) {
                    canStop = true;
                }
                return HookStatus.RET(emulator, originFunction);
            }
        });
        ixHook.register(executable.getName(), "memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer dest = context.getPointerArg(0);
                Pointer src = context.getPointerArg(1);
                int size = context.getIntArg(2);
                Inspector.inspect(src.getByteArray(0, size), "memcpy dest=" + dest + ", src=" + src + ", LR=" + UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                return HookStatus.RET(emulator, originFunction);
            }
        });
        ixHook.refresh();

//        emulator.traceCode(module.base, module.base + module.size);
//        Debugger debugger = emulator.attach();
//        debugger.addBreakPoint(module, 0x0246c);
//        debugger.addBreakPoint(module, 0x0260c);
//        emulator.traceWrite(0xbffff694L, 0xbffff694L + 4);

        while (!canStop) {
            long start = System.currentTimeMillis();
            String pwd = "password";
            System.err.println("exit code: " + module.callEntry(emulator, pwd) + ", offset=" + (System.currentTimeMillis() - start) + "ms" + ", pwd=" + pwd);
            canStop = true;
        }
    }

}
