package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.arm.Arm64Svc;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.hook.BaseHook;
import cn.banny.emulator.hook.ReplaceCallback;
import cn.banny.emulator.linux.Module;
import cn.banny.emulator.linux.Symbol;
import cn.banny.emulator.memory.SvcMemory;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class HookZz extends BaseHook implements IHookZz {

    private static final Log log = LogFactory.getLog(HookZz.class);

    private static HookZz instance;

    public static HookZz getInstance(Emulator emulator) {
        if (instance == null) {
            try {
                instance = new HookZz(emulator);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return instance;
    }

    private final Symbol zz_enable_arm_arm64_b_branch, zz_disable_arm_arm64_b_branch;

    private final Symbol zzReplace;
    private final Symbol zzWrap;

    private HookZz(Emulator emulator) throws IOException {
        super(emulator);

        Module module = emulator.getMemory().load(resolveLibrary(emulator, "libhookzz.so"));
        zz_enable_arm_arm64_b_branch = module.findSymbolByName("zz_enable_arm_arm64_b_branch");
        zz_disable_arm_arm64_b_branch = module.findSymbolByName("zz_disable_arm_arm64_b_branch");
        zzReplace = module.findSymbolByName("ZzReplace");
        zzWrap = module.findSymbolByName("ZzWrap");
        log.debug("zzReplace=" + zzReplace + ", zzWrap=" + zzWrap);

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
        final Pointer originCall = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replaceCall = createReplacePointer(callback, originCall);
        int ret = zzReplace.call(emulator, functionAddress, replaceCall, originCall)[0].intValue();
        if (ret != RS_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    @Override
    public void replace(Symbol symbol, ReplaceCallback callback) {
        replace(symbol.getAddress(), callback);
    }

    @Override
    public <T extends RegisterContext> void wrap(Symbol symbol, WrapCallback<T> callback) {
        wrap(symbol.getAddress(), callback);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends RegisterContext> void wrap(long functionAddress, final WrapCallback<T> callback) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        final Map<String, Object> context = new HashMap<>();
        Pointer preCall = svcMemory.registerSvc(emulator.getPointerSize() == 4 ? new ArmSvc() {
            @Override
            public int handle(Unicorn u, Emulator emulator) {
                context.clear();
                callback.preCall(u, (T) new Arm32RegisterContextImpl(emulator, context), new ArmHookEntryInfo(emulator));
                return 0;
            }
        } : new Arm64Svc() {
            @Override
            public int handle(Unicorn u, Emulator emulator) {
                context.clear();
                callback.preCall(u, (T) new Arm64RegisterContextImpl(emulator, context), new Arm64HookEntryInfo(emulator));
                return 0;
            }
        });
        Pointer postCall = svcMemory.registerSvc(emulator.getPointerSize() == 4 ? new ArmSvc() {
            @Override
            public int handle(Unicorn u, Emulator emulator) {
                callback.postCall(u, (T) new Arm32RegisterContextImpl(emulator, context), new ArmHookEntryInfo(emulator));
                return 0;
            }
        } : new Arm64Svc() {
            @Override
            public int handle(Unicorn u, Emulator emulator) {
                callback.postCall(u, (T) new Arm64RegisterContextImpl(emulator, context), new Arm64HookEntryInfo(emulator));
                return 0;
            }
        });
        int ret = zzWrap.call(emulator, functionAddress, preCall, postCall)[0].intValue();
        if (ret != RS_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

}
