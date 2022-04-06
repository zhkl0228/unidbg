package org.aeonlucid;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.android.EmulatorTest;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

public class AndroidNativeEmuTest extends EmulatorTest<AndroidEmulator> {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    public void testExample() {
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libnative-lib.so"));

        emulator.traceCode();
        Number number = module.callFunction(emulator, 0x7e0 + 1);
        System.out.println("eFunc length is: " + number.intValue());

        emulator.traceCode();
        number = module.callFunction(emulator, 0x7e0 + 1);
        System.out.println("eFunc length is: " + number.intValue());
    }

    public void testCallTest() {
        Module module = emulator.loadLibrary(new File("src/test/resources/example_binaries/libnative-lib.so"));

        Number number = module.callFunction(emulator, "_Z4testv");
        System.out.println("String length is: " + number.intValue());
    }

    @Override
    protected AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder.for32Bit().setProcessName(getClass().getSimpleName()).build();
    }
}
