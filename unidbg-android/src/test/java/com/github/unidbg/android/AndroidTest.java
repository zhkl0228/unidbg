package com.github.unidbg.android;

import com.github.unidbg.*;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM32SyscallHandler;
import com.github.unidbg.linux.android.AndroidARMEmulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.struct.Dirent;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;
import java.util.Collections;

public class AndroidTest extends AbstractJni {

    public static void main(String[] args) throws IOException {
        new AndroidTest().test();
    }

    private final AndroidEmulator emulator;
    private final Module module;

    private static class MyARMSyscallHandler extends ARM32SyscallHandler {
        private MyARMSyscallHandler(SvcMemory svcMemory) {
            super(svcMemory);
        }
        @Override
        protected int fork(Emulator<?> emulator) {
            return emulator.getPid();
        }
    }

    private AndroidTest() throws IOException {
        final File executable = new File("unidbg-android/src/test/native/android/libs/armeabi-v7a/test");
        emulator = new AndroidARMEmulator(executable.getName(),
                new File("target/rootfs"),
                Collections.<BackendFactory>singleton(new DynarmicFactory(true))) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new MyARMSyscallHandler(svcMemory);
            }
        };
        Memory memory = emulator.getMemory();
        emulator.getSyscallHandler().setVerbose(false);
        LibraryResolver resolver = new AndroidResolver(19);
        memory.setLibraryResolver(resolver);

        module = emulator.loadLibrary(executable, true);

        VM vm = emulator.createDalvikVM(null);
        vm.setVerbose(true);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/native/android/libs/armeabi-v7a/libnative.so"), true);
        dm.callJNI_OnLoad(emulator);

        {
            Pointer pointer = memory.allocateStack(0x100);
            System.out.println(new Dirent(pointer));
        }
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if ("com/github/unidbg/android/AndroidTest->testStaticFloat()F".equals(signature)) {
            return 0.0023942017F;
        }

        return super.callStaticFloatMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("com/github/unidbg/android/AndroidTest->staticBooleanField:Z".equals(signature)) {
            return true;
        }

        return super.getStaticBooleanField(vm, dvmClass, signature);
    }

    private void test() {
//        Logger.getLogger("com.github.unidbg.linux.ARM32SyscallHandler").setLevel(Level.DEBUG);
        System.err.println("exit code: " + module.callEntry(emulator));
    }

}
