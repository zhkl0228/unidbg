package com.github.unidbg;

import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.dvm.VM;

import java.io.File;

public interface AndroidEmulator extends ARMEmulator<AndroidFileIO> {

    /**
     * @param apkFile 可为null
     */
    VM createDalvikVM(File apkFile);

    @SuppressWarnings("unused")
    VM getDalvikVM();

}
