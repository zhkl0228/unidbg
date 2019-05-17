package org.telegram.messenger;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.linux.android.AndroidARM64Emulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.ByteArray;
import cn.banny.unidbg.linux.android.dvm.DalvikModule;
import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class Utilities64 {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARM64Emulator("org.telegram.messenger");
    }

    private final ARMEmulator emulator;
    private final VM vm;

    private final DvmClass Utilities;

    private Utilities64() throws IOException {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(null);
        DalvikModule dm = vm.loadLibrary(new File("src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so"), false);
        dm.callJNI_OnLoad(emulator);

        Utilities = vm.resolveClass("org/telegram/messenger/Utilities");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public static void main(String[] args) throws Exception {
        Utilities64 test = new Utilities64();

        test.aesCbcEncryptionByteArray();
        test.aesCtrDecryptionByteArray();
        test.pbkdf2();

        test.destroy();
    }

    private void aesCbcEncryptionByteArray() {
        long start = System.currentTimeMillis();
        ByteArray data = new ByteArray(new byte[16]);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        Number ret = Utilities.callStaticJniMethod(emulator, "aesCbcEncryptionByteArray([B[B[BIIII)V", vm.addLocalObject(data),
                vm.addLocalObject(new ByteArray(key)),
                vm.addLocalObject(new ByteArray(iv)),
                0, data.length(), 0, 0);
        vm.deleteLocalRefs();
        Inspector.inspect(data.getValue(), "aesCbcEncryptionByteArray ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private void aesCtrDecryptionByteArray() {
        long start = System.currentTimeMillis();
        ByteArray data = new ByteArray(new byte[16]);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        Number ret = Utilities.callStaticJniMethod(emulator, "aesCtrDecryptionByteArray([B[B[BIII)V", vm.addLocalObject(data),
                vm.addLocalObject(new ByteArray(key)),
                vm.addLocalObject(new ByteArray(iv)),
                0, data.length(), 0);
        vm.deleteLocalRefs();
        Inspector.inspect(data.getValue(), "aesCtrDecryptionByteArray ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private void pbkdf2() {
        long start = System.currentTimeMillis();
        byte[] password = "123456".getBytes();
        byte[] salt = new byte[8];
        ByteArray dst = new ByteArray(new byte[64]);
        Number ret = Utilities.callStaticJniMethod(emulator, "pbkdf2([B[B[BI)V", vm.addLocalObject(new ByteArray(password)),
                vm.addLocalObject(new ByteArray(salt)),
                vm.addLocalObject(dst), 100000);
        vm.deleteLocalRefs();
        Inspector.inspect(dst.getValue(), "pbkdf2 ret=" + ret + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
