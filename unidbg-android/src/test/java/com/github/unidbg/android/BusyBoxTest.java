package com.github.unidbg.android;

import com.github.unidbg.arm.backend.dynarmic.DynarmicLoader;

import java.io.File;
import java.io.IOException;

public class BusyBoxTest {

    public static void main(String[] args) throws IOException {
        DynarmicLoader.useDynarmic();
        RunExecutable.run(new File("unidbg-android/src/test/resources/example_binaries/busybox"), null, "wget", "http://pv.sohu.com/cityjson?ie=utf-8", "-O", "-");
    }

}
