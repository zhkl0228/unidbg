package org.telegram.messenger;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.arm.backend.KvmFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyClassFactory;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import junit.framework.TestCase;

import java.io.File;
import java.io.IOException;

/**
 * mvn test -Dmaven.test.skip=false -Dtest=org.telegram.messenger.Utilities64
 */
public class Utilities64 extends TestCase {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder
                .for64Bit()
                .setProcessName("org.telegram.messenger")
                .addBackendFactory(new HypervisorFactory(true))
                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new KvmFactory(true))
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
    }

    private final AndroidEmulator emulator;
    private final VM vm;

    private final DvmClass cUtilities;

    public Utilities64() {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());

        vm = emulator.createDalvikVM();
        vm.setDvmClassFactory(new ProxyClassFactory());
        Module module = new JniGraphics(emulator, vm).register(memory);
        assert module != null;
        new AndroidModule(emulator, vm).register(memory);

        System.out.println("backend=" + emulator.getBackend());
        vm.setVerbose(true);
        File file = new File("src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so");
        DalvikModule dm = vm.loadLibrary(file.canRead() ? file : new File("unidbg-android/src/test/resources/example_binaries/arm64-v8a/libtmessages.29.so"), true);
        dm.callJNI_OnLoad(emulator);

        cUtilities = vm.resolveClass("org/telegram/messenger/Utilities");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy");
    }

    public void test() throws Exception {
        this.aesCbcEncryptionByteArray();
        this.aesCtrDecryptionByteArray();
        this.pbkdf2();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        destroy();
    }

    public static void main(String[] args) throws Exception {
        final Utilities64 test = new Utilities64();

        Thread thread = new Thread(test::pbkdf2);
        thread.start();
        thread.join();

        test.aesCbcEncryptionByteArray();
        test.aesCtrDecryptionByteArray();
        test.pbkdf2();

        test.destroy();
    }

    private void aesCbcEncryptionByteArray() {
        long start = System.currentTimeMillis();
        ByteArray data = new ByteArray(vm, new byte[16]);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        cUtilities.callStaticJniMethod(emulator, "aesCbcEncryptionByteArray([B[B[BIIII)V", data,
                key,
                iv,
                0, data.length(), 0, 0);
        Inspector.inspect(data.getValue(), "aesCbcEncryptionByteArray offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private void aesCtrDecryptionByteArray() {
        long start = System.currentTimeMillis();
        ByteArray data = new ByteArray(vm, new byte[16]);
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        cUtilities.callStaticJniMethod(emulator, "aesCtrDecryptionByteArray([B[B[BIII)V", data,
                key,
                iv,
                0, data.length(), 0);
        Inspector.inspect(data.getValue(), "[" + emulator.getBackend() + "]aesCtrDecryptionByteArray offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private void pbkdf2() {
        byte[] password = "123456".getBytes();
        byte[] salt = new byte[8];
        ByteArray dst = new ByteArray(vm, new byte[64]);
        for (int i = 0; i < 3; i++) {
            long start = System.currentTimeMillis();
            cUtilities.callStaticJniMethod(emulator, "pbkdf2([B[B[BI)V", password,
                    salt,
                    dst, 100000);
            Inspector.inspect(dst.getValue(), String.format("[%s]pbkdf2 offset=%sms, backend=%s", Thread.currentThread().getName(), System.currentTimeMillis() - start, emulator.getBackend()));
        }
    }

}
