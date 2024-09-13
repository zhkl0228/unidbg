package com.github.unidbg.hook;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.ios.hook.FishHook;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HookLoader extends BaseHook {

    private static final Logger log = LoggerFactory.getLogger(HookLoader.class);

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
    private final Symbol _hook_dispatch_async;

    private HookLoader(Emulator<?> emulator) {
        super(emulator, "libhook");

        _hook_objc_msgSend = module.findSymbolByName("_hook_objc_msgSend", false);
        if (_hook_objc_msgSend == null) {
            throw new IllegalStateException("find _hook_objc_msgSend failed");
        }

        _hook_dispatch_async = module.findSymbolByName("_hook_dispatch_async", false);
        if (_hook_dispatch_async == null) {
            throw new IllegalStateException("find _hook_dispatch_async failed");
        }
    }

    private boolean objcMsgSendHooked;

    public synchronized void hookObjcMsgSend(final MsgSendCallback callback) {
        if (objcMsgSendHooked) {
            throw new IllegalStateException("objc_msgSend already hooked.");
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

    private boolean dispatchAsyncHooked;

    public synchronized void hookDispatchAsync(final DispatchAsyncCallback callback) {
        if (dispatchAsyncHooked) {
            throw new IllegalStateException("dispatch_async already hooked.");
        }
        if (emulator.is32Bit()) {
            throw new UnsupportedOperationException();
        }

        SvcMemory svcMemory = emulator.getSvcMemory();
        Pointer pointer = callback == null ? null : svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                return dispatch_callback(emulator, callback);
            }
        });
        _hook_dispatch_async.call(emulator, pointer);

        dispatchAsyncHooked = true;
    }

    private long dispatch_callback(Emulator<?> emulator, DispatchAsyncCallback callback) {
        RegisterContext context = emulator.getContext();
        Pointer dq = context.getPointerArg(0);
        Pointer block = context.getPointerArg(1);
        Pointer fun = block.getPointer(0x10);
        boolean is_barrier_async = context.getIntArg(2) != 0;
        DispatchAsyncCallback.Result dispatch = callback.canDispatch(emulator, dq, fun, is_barrier_async);
        if (dispatch == null) {
            dispatch = DispatchAsyncCallback.Result.skip;
        }
        if (dispatch == DispatchAsyncCallback.Result.skip && (log.isDebugEnabled() || LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled())) {
            System.err.println("Skip dispatch_async dq=" + dq + ", fun=" + fun);
        }
        return dispatch.ordinal();
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
