package com.easyso.test;


import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class TestEasy extends AbstractJni {

    private final AndroidEmulator emulator;
    private final DvmClass dvmClass;
    private String className = "com/roysue/easyso1/MainActivity";
    private String soFile = "unidbg-android/src/test/resources/mcto/libroysue.so";

    public TestEasy(){
        emulator = createAndroidEmulator();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        VM vm = createVM();
        vm.setJni(this);
        vm.setVerbose(true);
        vm.loadLibrary(new File(soFile), false);
        dvmClass = vm.resolveClass(className);
    }

    private LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    public static void main(String[] args) throws IOException {
        TestEasy testEasy = new TestEasy();
        testEasy.start();
        testEasy.stop();
    }

    private AndroidEmulator createAndroidEmulator(){
        String processName = "com.roysue.easyso1";
        return  AndroidEmulatorBuilder
                .for32Bit()
                .setProcessName(processName).build();
    }

    private VM createVM() {
        return emulator.createDalvikVM(null);
    }

    private void start(){
        DvmObject<?> result = dvmClass.callStaticJniMethodObject(emulator,"Java_com_roysue_easyso1_MainActivity_stringFromJNI()Ljava/lang/String");
        System.out.println("result = " + result.getValue());
    }

    private void stop() throws IOException {
        emulator.close();
    }
}
