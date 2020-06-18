package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.ios.hook.FishHook;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;

public class HookLoader extends BaseHook {

    public static HookLoader load(Emulator<?> emulator) {
        Substrate.getInstance(emulator); // load substrate first
        FishHook.getInstance(emulator); // load fishhook

        HookLoader loader = emulator.get(HookLoader.class.getName());
        if (loader == null) {
            loader = new HookLoader(emulator);
            emulator.set(HookLoader.class.getName(), loader);
        }
        return loader;
    }

    private final Symbol _hook_objc_msgSend;

    private HookLoader(Emulator<?> emulator) {
        super(emulator, "libhook");

        _hook_objc_msgSend = module.findSymbolByName("_hook_objc_msgSend", false);
        if (_hook_objc_msgSend == null) {
            throw new IllegalStateException("find _hook_objc_msgSend failed");
        }
    }

    private boolean objcMsgSendHooked;

    public synchronized void hookObjcMsgSend(final MsgSendCallback callback) {
        if (objcMsgSendHooked) {
            throw new IllegalStateException("objc_msgSend already hooked");
        }

        SvcMemory svcMemory = emulator.getSvcMemory();
        Pointer pointer = callback == null ? null : svcMemory.registerSvc(emulator.is64Bit() ? new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return objc_msgSend_callback(emulator, callback);
            }
        } : new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return objc_msgSend_callback(emulator, callback);
            }
        });
        _hook_objc_msgSend.call(emulator, pointer);
        objcMsgSendHooked = true;
    }

    private long objc_msgSend_callback(Emulator<?> emulator, MsgSendCallback callback) {
        RegisterContext context = emulator.getContext();
        boolean systemClass = context.getIntArg(0) != 0;
        Pointer classNamePointer = context.getPointerArg(1);
        String cmd = context.getPointerArg(2).getString(0);
        Pointer lr = context.getPointerArg(3);
        callback.onMsgSend(emulator, systemClass, classNamePointer == null ? null : classNamePointer.getString(0), cmd, lr);
        return 0;
    }

}
