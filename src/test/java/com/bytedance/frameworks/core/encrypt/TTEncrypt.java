package com.bytedance.frameworks.core.encrypt;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.hookzz.*;
import cn.banny.unidbg.hook.xhook.IxHook;
import cn.banny.unidbg.hook.xhook.XHookImpl;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.ByteArray;
import cn.banny.unidbg.linux.android.dvm.DalvikModule;
import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import unicorn.ArmConst;
import unicorn.Unicorn;

import java.io.File;
import java.io.IOException;

public class TTEncrypt {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator("com.qidian.dldl.official");
    }

    private final ARMEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass TTEncryptUtils;

    private TTEncrypt() throws IOException {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
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
        hookZz.wrap(module.findSymbolByName("ss_encrypt"), new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                Pointer pointer = ctx.getR2Pointer();
                int length = (int) ctx.getR3();
                byte[] key = pointer.getByteArray(0, length);
                Inspector.inspect(key, "ss_encrypt key");
            }
            @Override
            public void postCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("ss_encrypt.postCall R0=" + ctx.getR0());
            }
        });
        hookZz.wrap(module.base + 0x00000F5C + 1, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                System.out.println("R3=" + ctx.getR3() + ", R10=0x" + Long.toHexString(ctx.getR10()));
            }
        });

        hookZz.enable_arm_arm64_b_branch();
        hookZz.replace(module.findSymbolByName("ss_encrypted_size"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Number arg0 = (Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R0);
                System.out.println("ss_encrypted_size.onCall arg0=" + arg0.intValue() + ", originFunction=0x" + Long.toHexString(originFunction));
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        hookZz.disable_arm_arm64_b_branch();

        IxHook xHook = XHookImpl.getInstance(emulator);
        xHook.register("libttEncrypt.so", "strlen", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                System.out.println("strlen=" + pointer.getString(0));
                return HookStatus.RET(emulator.getUnicorn(), originFunction);
            }
        });
        xHook.register("libttEncrypt.so", "memmove", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int length = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                Inspector.inspect(src.getByteArray(0, length), "memmove dest=" + dest);
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        xHook.register("libttEncrypt.so", "memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int length = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                Inspector.inspect(src.getByteArray(0, length), "memcpy dest=" + dest);
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        xHook.refresh();

        long start = System.currentTimeMillis();
        byte[] data = new byte[16];
        Number ret = TTEncryptUtils.callStaticJniMethod(emulator, "ttEncrypt([BI)[B", vm.addLocalObject(new ByteArray(data)), data.length);
        long hash = ret.intValue() & 0xffffffffL;
        ByteArray array = vm.getObject(hash);
        vm.deleteLocalRefs();
        Inspector.inspect(array.getValue(), "ttEncrypt ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
