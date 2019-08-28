package com.bytedance.frameworks.core.encrypt;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.Arm32RegisterContext;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.debugger.DebuggerType;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.hookzz.HookEntryInfo;
import cn.banny.unidbg.hook.hookzz.HookZz;
import cn.banny.unidbg.hook.hookzz.IHookZz;
import cn.banny.unidbg.hook.hookzz.WrapCallback;
import cn.banny.unidbg.hook.xhook.IxHook;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.XHookImpl;
import cn.banny.unidbg.linux.android.dvm.array.ByteArray;
import cn.banny.unidbg.linux.android.dvm.DalvikModule;
import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.Memory;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

public class TTEncrypt {

    private final ARMEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass TTEncryptUtils;

    private TTEncrypt() throws IOException {
        emulator = new AndroidARMEmulator("com.qidian.dldl.official");
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(null);
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

    private void ttEncrypt() throws IOException {
        Symbol sbox0 = module.findSymbolByName("sbox0");
        Symbol sbox1 = module.findSymbolByName("sbox1");
        Inspector.inspect(sbox0.createPointer(emulator).getByteArray(0, 256), "sbox0");
        Inspector.inspect(sbox1.createPointer(emulator).getByteArray(0, 256), "sbox1");

        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.wrap(module.findSymbolByName("ss_encrypt"), new WrapCallback<RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, RegisterContext ctx, HookEntryInfo info) {
                Pointer pointer = ctx.getPointerArg(2);
                int length = ctx.getIntArg(3);
                byte[] key = pointer.getByteArray(0, length);
                Inspector.inspect(key, "ss_encrypt key");
            }
            @Override
            public void postCall(Emulator emulator, RegisterContext ctx, HookEntryInfo info) {
                System.out.println("ss_encrypt.postCall R0=" + ctx.getLongArg(0));
            }
        });
        hookZz.wrap(module.base + 0x00000F5C + 1, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("R3=" + ctx.getLongArg(3) + ", R10=0x" + Long.toHexString(ctx.getR10Long()));
            }
        });

        hookZz.enable_arm_arm64_b_branch();
        hookZz.replace(module.findSymbolByName("ss_encrypted_size"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                System.out.println("ss_encrypted_size.onCall arg0=" + emulator.getContext().getIntArg(0) + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(emulator, originFunction);
            }
        });
        hookZz.disable_arm_arm64_b_branch();

        IxHook xHook = XHookImpl.getInstance(emulator);
        xHook.register("libttEncrypt.so", "strlen", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Pointer pointer = emulator.getContext().getPointerArg(0);
                System.out.println("strlen=" + pointer.getString(0));
                return HookStatus.RET(emulator, originFunction);
            }
        });
        xHook.register("libttEncrypt.so", "memmove", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
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
            public HookStatus onCall(Emulator emulator, long originFunction) {
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
//        emulator.attach(DebuggerType.GDB_SERVER);
        Number ret = TTEncryptUtils.callStaticJniMethod(emulator, "ttEncrypt([BI)[B", vm.addLocalObject(new ByteArray(data)), data.length);
        long hash = ret.intValue() & 0xffffffffL;
        ByteArray array = vm.getObject(hash);
        vm.deleteLocalRefs();
        Inspector.inspect(array.getValue(), "ttEncrypt ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
