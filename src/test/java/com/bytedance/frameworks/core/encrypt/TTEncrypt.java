package com.bytedance.frameworks.core.encrypt;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.Arm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.DebuggerType;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.hook.xhook.IxHook;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.XHookImpl;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

public class TTEncrypt {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass TTEncryptUtils;

    private TTEncrypt() throws IOException {
        emulator = new AndroidARMEmulator("com.qidian.dldl.official");
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(null);
        vm.setVerbose(true);
        DalvikModule dm = vm.loadLibrary(new File("src/test/resources/example_binaries/libttEncrypt.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        TTEncryptUtils = vm.resolveClass("com/bytedance/frameworks/core/encrypt/TTEncryptUtils");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        TTEncrypt test = new TTEncrypt();

        test.ttEncrypt();

        test.destroy();
    }

    private void ttEncrypt() {
        Symbol sbox0 = module.findSymbolByName("sbox0");
        Symbol sbox1 = module.findSymbolByName("sbox1");
        Inspector.inspect(sbox0.createPointer(emulator).getByteArray(0, 256), "sbox0");
        Inspector.inspect(sbox1.createPointer(emulator).getByteArray(0, 256), "sbox1");

        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.wrap(module.findSymbolByName("ss_encrypt"), new WrapCallback<RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
                Pointer pointer = ctx.getPointerArg(2);
                int length = ctx.getIntArg(3);
                byte[] key = pointer.getByteArray(0, length);
                Inspector.inspect(key, "ss_encrypt key");
            }
            @Override
            public void postCall(Emulator<?> emulator, RegisterContext ctx, HookEntryInfo info) {
                System.out.println("ss_encrypt.postCall R0=" + ctx.getLongArg(0));
            }
        });
        hookZz.wrap(module.base + 0x00000F5C + 1, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("R3=" + ctx.getLongArg(3) + ", R10=0x" + Long.toHexString(ctx.getR10Long()));
            }
        });

        hookZz.enable_arm_arm64_b_branch();
        hookZz.replace(module.findSymbolByName("ss_encrypted_size"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("ss_encrypted_size.onCall arg0=" + context.getIntArg(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator, originFunction);
            }
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                System.out.println("ss_encrypted_size.postCall ret=" + context.getIntArg(0));
            }
        }, true);
        hookZz.disable_arm_arm64_b_branch();

        IxHook xHook = XHookImpl.getInstance(emulator);
        xHook.register("libttEncrypt.so", "strlen", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                Pointer pointer = context.getPointerArg(0);
                String str = pointer.getString(0);
                System.out.println("strlen=" + str);
                context.push(str);
                return HookStatus.RET(emulator, originFunction);
            }
            @Override
            public void postCall(Emulator<?> emulator, HookContext context) {
                System.out.println("strlen=" + context.pop() + ", ret=" + context.getIntArg(0));
            }
        }, true);
        xHook.register("libttEncrypt.so", "memmove", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer dest = context.getPointerArg(0);
                Pointer src = context.getPointerArg(1);
                int length = context.getIntArg(2);
                Inspector.inspect(src.getByteArray(0, length), "memmove dest=" + dest);
                return HookStatus.RET(emulator, originFunction);
            }
        });
        xHook.register("libttEncrypt.so", "memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                RegisterContext context = emulator.getContext();
                Pointer dest = context.getPointerArg(0);
                Pointer src = context.getPointerArg(1);
                int length = context.getIntArg(2);
                Inspector.inspect(src.getByteArray(0, length), "memcpy dest=" + dest);
                return HookStatus.RET(emulator, originFunction);
            }
        });
        xHook.refresh();

        long start = System.currentTimeMillis();
        byte[] data = new byte[16];
        emulator.attach(DebuggerType.ANDROID_SERVER_V7);
        Number ret = TTEncryptUtils.callStaticJniMethod(emulator, "ttEncrypt([BI)[B", vm.addLocalObject(new ByteArray(data)), data.length);
        long hash = ret.intValue() & 0xffffffffL;
        ByteArray array = vm.getObject(hash);
        vm.deleteLocalRefs();
        Inspector.inspect(array.getValue(), "ttEncrypt ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
