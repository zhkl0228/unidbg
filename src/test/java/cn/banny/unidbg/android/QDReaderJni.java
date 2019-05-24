package cn.banny.unidbg.android;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.xhook.IxHook;
import cn.banny.unidbg.linux.android.XHookImpl;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.memory.Memory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;

public class QDReaderJni extends AbstractJni {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator("a.d.c");
    }

    private final ARMEmulator emulator;
    private final VM vm;

    private final DvmClass d;

    private QDReaderJni() throws IOException {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(null);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary(new File("src/test/resources/example_binaries/armeabi-v7a/libd-lib.so"), false);
        dm.callJNI_OnLoad(emulator);

        d = vm.resolveClass("a/d");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        QDReaderJni test = new QDReaderJni();

        test.c();

        test.destroy();
    }

    private void c() throws Exception {
        IxHook xHook = XHookImpl.getInstance(emulator);
        xHook.register("libd-lib.so", "free", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                return HookStatus.LR(emulator.getUnicorn(), 0);
            }
        });
        xHook.refresh();

        final String data = "359250054370919||1551086094";
        long start = System.currentTimeMillis();
        Number ret = d.callStaticJniMethod(emulator, "c(Ljava/lang/String;)[B", vm.addLocalObject(new StringObject(vm, data)));
        long hash = ret.intValue() & 0xffffffffL;
        ByteArray array = vm.getObject(hash);
        vm.deleteLocalRefs();
        Inspector.inspect(array.getValue(), "c ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        final String key = "sewxf03hhz3ew9qcCXMHiDMk";
        final String iv = "sh331nt1";

        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        DESedeKeySpec keySpec = new DESedeKeySpec(key.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv.getBytes()));
        byte[] encrypted = cipher.doFinal(data.getBytes());
        Inspector.inspect(encrypted, "Encrypted");

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv.getBytes()));
        byte[] decrypted = cipher.doFinal(array.getValue());
        Inspector.inspect(decrypted, "Decrypted");
    }

}
