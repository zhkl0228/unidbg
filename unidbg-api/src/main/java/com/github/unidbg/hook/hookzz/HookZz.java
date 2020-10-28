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
 * 对32位支持比较好
 */
public final class HookZz extends BaseHook implements IHookZz {

    private static final Log log = LogFactory.getLog(HookZz.class);

    public static HookZz getInstance(Emulator<?> emulator) {
        HookZz hookZz = emulator.get(HookZz.class.getName());
        if (hookZz == null) {
            hookZz = new HookZz(emulator);
            emulator.set(HookZz.class.getName(), hookZz);
        }
        return hookZz;
    }

    private static final int RS_SUCCESS = 1;

    private final Symbol zz_enable_arm_arm64_b_branch, zz_disable_arm_arm64_b_branch;

    private final Symbol zzReplace;
    private final Symbol zzWrap;
    private final Symbol zzDynamicBinaryInstrumentation;

    private HookZz(Emulator<?> emulator) {
        super(emulator, "libhookzz");

        boolean isIOS = emulator.getFamily() == Family.iOS;
        zz_enable_arm_arm64_b_branch = module.findSymbolByName(isIOS ? "_zz_enable_arm_arm64_b_branch" : "zz_enable_arm_arm64_b_branch", false);
        zz_disable_arm_arm64_b_branch = module.findSymbolByName(isIOS ? "_zz_disable_arm_arm64_b_branch" : "zz_disable_arm_arm64_b_branch", false);
        zzReplace = module.findSymbolByName(isIOS ? "_ZzReplace" : "ZzReplace", false);
        zzWrap = module.findSymbolByName(isIOS ? "_ZzWrap" : "ZzWrap", false);
        zzDynamicBinaryInstrumentation = module.findSymbolByName(isIOS ? "_ZzDynamicBinaryInstrumentation" : "ZzDynamicBinaryInstrumentation", false);
        if (log.isDebugEnabled()) {
            log.debug("zzReplace=" + zzReplace + ", zzWrap=" + zzWrap);
        }

        if (zz_enable_arm_arm64_b_branch == null) {
            throw new IllegalStateException("zz_enable_arm_arm64_b_branch is null");
        }
        if (zz_disable_arm_arm64_b_branch == null) {
            throw new IllegalStateException("zz_disable_arm_arm64_b_branch is null");
        }
        if (zzReplace == null) {
            throw new IllegalStateException("zzReplace is null");
        }
        if (zzWrap == null) {
            throw new IllegalStateException("zzWrap is null");
        }
        if (zzDynamicBinaryInstrumentation == null) {
            throw new IllegalStateException("zzDynamicBinaryInstrumentation is null");
        }
    }

    @Override
    public void enable_arm_arm64_b_branch() {
        int ret = zz_enable_arm_arm64_b_branch.call(emulator)[0].intValue();
        if (ret != RS_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void disable_arm_arm64_b_branch() {
        int ret = zz_disable_arm_arm64_b_branch.call(emulator)[0].intValue();
        if (ret != RS_SUCCESS) {
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
        int ret = zzReplace.call(emulator, UnidbgPointer.pointer(emulator, functionAddress), replaceCall, originCall)[0].intValue();
        if (ret != RS_SUCCESS) {
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

    @SuppressWarnings("unchecked")
    @Override
    public <T extends RegisterContext> void wrap(long functionAddress, final WrapCallback<T> callback) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        final Stack<Object> context = new Stack<>();
        Pointer preCall = svcMemory.registerSvc(emulator.is32Bit() ? new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                callback.preCall(emulator, (T) new HookZzArm32RegisterContextImpl(emulator, context), new ArmHookEntryInfo(emulator));
                return 0;
            }
        } : new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                callback.preCall(emulator, (T) new HookZzArm64RegisterContextImpl(emulator, context), new Arm64HookEntryInfo(emulator));
                return 0;
            }
        });
        Pointer postCall = svcMemory.registerSvc(emulator.is32Bit() ? new ArmSvc() {
            @Override
            public long handle(Emulator<?> emulator) {
                callback.postCall(emulator, (T) new HookZzArm32RegisterContextImpl(emulator, context), new ArmHookEntryInfo(emulator));
                return 0;
            }
        } : new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                callback.postCall(emulator, (T) new HookZzArm64RegisterContextImpl(emulator, context), new Arm64HookEntryInfo(emulator));
                return 0;
            }
        });
        int ret = zzWrap.call(emulator, UnidbgPointer.pointer(emulator, functionAddress), preCall, postCall)[0].intValue();
        if (ret != RS_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public <T extends RegisterContext> void instrument(Symbol symbol, InstrumentCallback<T> callback) {
        instrument(symbol.getAddress(), callback);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends RegisterContext> void instrument(long functionAddress, final InstrumentCallback<T> callback) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        Pointer dbiCall = svcMemory.registerSvc(emulator.is32Bit() ? new ArmSvc() {
            private final Stack<Object> context = new Stack<>();
            @Override
            public long handle(Emulator<?> emulator) {
                callback.dbiCall(emulator, (T) new HookZzArm32RegisterContextImpl(emulator, context), new ArmHookEntryInfo(emulator));
                return 0;
            }
        } : new Arm64Svc() {
            private final Stack<Object> context = new Stack<>();
            @Override
            public long handle(Emulator<?> emulator) {
                callback.dbiCall(emulator, (T) new HookZzArm64RegisterContextImpl(emulator, context), new Arm64HookEntryInfo(emulator));
                return 0;
            }
        });
        int ret = zzDynamicBinaryInstrumentation.call(emulator, UnidbgPointer.pointer(emulator, functionAddress), dbiCall)[0].intValue();
        if (ret != RS_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void switch_to_file_log(String path) {
        throw new UnsupportedOperationException();
    }
}
