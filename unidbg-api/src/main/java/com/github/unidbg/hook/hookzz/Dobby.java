package com.github.unidbg.hook.hookzz;

import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.ArmSvc;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Stack;

/**
 * 对64位支持比较好
 */
public final class Dobby extends BaseHook implements IHookZz {

    private static final Log log = LogFactory.getLog(Dobby.class);

    public static Dobby getInstance(Emulator<?> emulator) {
        Dobby dobby = emulator.get(Dobby.class.getName());
        if (dobby == null) {
            dobby = new Dobby(emulator);
            emulator.set(Dobby.class.getName(), dobby);
        }
        return dobby;
    }

    private static final int RT_SUCCESS = 0;

    private final Symbol dobby_enable_near_branch_trampoline, dobby_disable_near_branch_trampoline;
    private final Symbol switch_to_file_log;

    private final Symbol dobbyHook;
    private final Symbol dobbyInstrument;

    private Dobby(Emulator<?> emulator) {
        super(emulator, "libdobby");

        boolean isIOS = emulator.getFamily() == Family.iOS;
        dobby_enable_near_branch_trampoline = module.findSymbolByName(isIOS ? "_dobby_enable_near_branch_trampoline" : "dobby_enable_near_branch_trampoline", false);
        dobby_disable_near_branch_trampoline = module.findSymbolByName(isIOS ? "_dobby_disable_near_branch_trampoline" : "dobby_disable_near_branch_trampoline", false);
        dobbyHook = module.findSymbolByName(isIOS ? "_DobbyHook" : "DobbyHook", false);
        dobbyInstrument = module.findSymbolByName(isIOS ? "_DobbyInstrument" : "DobbyInstrument", false);
        if (log.isDebugEnabled()) {
            log.debug("dobbyHook=" + dobbyHook + ", dobbyInstrument=" + dobbyInstrument);
        }

        if (dobby_enable_near_branch_trampoline == null && emulator.is64Bit()) {
            throw new IllegalStateException("dobby_enable_near_branch_trampoline is null");
        }
        if (dobby_disable_near_branch_trampoline == null && emulator.is64Bit()) {
            throw new IllegalStateException("dobby_disable_near_branch_trampoline is null");
        }
        if (dobbyHook == null) {
            throw new IllegalStateException("dobbyHook is null");
        }
        if (dobbyInstrument == null) {
            throw new IllegalStateException("dobbyInstrument is null");
        }

        switch_to_file_log = module.findSymbolByName(isIOS ? "_switch_to_file_log" : "switch_to_file_log", false);
    }

    @Override
    public void switch_to_file_log(String path) {
        if (switch_to_file_log == null) {
            throw new UnsupportedOperationException();
        }
        switch_to_file_log.call(emulator, path);
    }

    @Override
    public void enable_arm_arm64_b_branch() {
        if (dobby_enable_near_branch_trampoline == null) {
            return;
        }
        int ret = dobby_enable_near_branch_trampoline.call(emulator)[0].intValue();
        if (ret != RT_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void disable_arm_arm64_b_branch() {
        if (dobby_disable_near_branch_trampoline == null) {
            return;
        }
        int ret = dobby_disable_near_branch_trampoline.call(emulator)[0].intValue();
        if (ret != RT_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void replace(long functionAddress, final ReplaceCallback callback) {
        replace(functionAddress, callback, false);
    }

    @Override
    public void replace(Symbol symbol, ReplaceCallback callback) {
        replace(symbol, callback, false);
    }

    @Override
    public void replace(long functionAddress, ReplaceCallback callback, boolean enablePostCall) {
        final Pointer originCall = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replaceCall = createReplacePointer(callback, originCall, enablePostCall);
        int ret = dobbyHook.call(emulator, UnidbgPointer.pointer(emulator, functionAddress), replaceCall, originCall)[0].intValue();
        if (ret != RT_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void replace(Symbol symbol, ReplaceCallback callback, boolean enablePostCall) {
        replace(symbol.getAddress(), callback, enablePostCall);
    }

    @Override
    public <T extends RegisterContext> void wrap(Symbol symbol, WrapCallback<T> callback) {
        wrap(symbol.getAddress(), callback);
    }

    @Override
    public <T extends RegisterContext> void wrap(long functionAddress, final WrapCallback<T> callback) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T extends RegisterContext> void instrument(Symbol symbol, InstrumentCallback<T> callback) {
        instrument(symbol.getAddress(), callback);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends RegisterContext> void instrument(long functionAddress, final InstrumentCallback<T> callback) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        final Stack<Object> context = new Stack<>();
        Pointer dbiCall = svcMemory.registerSvc(emulator.is32Bit() ? new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                context.clear();
                callback.dbiCall(emulator, (T) new HookZzArm32RegisterContextImpl(emulator, context), new ArmHookEntryInfo(emulator));
                return 0;
            }
        } : new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                context.clear();
                callback.dbiCall(emulator, (T) new HookZzArm64RegisterContextImpl(emulator, context), new Arm64HookEntryInfo(emulator));
                return 0;
            }
        });
        int ret = dobbyInstrument.call(emulator, UnidbgPointer.pointer(emulator, functionAddress), dbiCall)[0].intValue();
        if (ret != RT_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }
}
