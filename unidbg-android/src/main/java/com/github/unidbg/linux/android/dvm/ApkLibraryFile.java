package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.android.dvm.apk.Apk;
import com.github.unidbg.spi.LibraryFile;

import java.nio.ByteBuffer;

class ApkLibraryFile implements LibraryFile {

    private final BaseVM baseVM;
    private final Apk apk;
    private final String soName;
    private final byte[] soData;
    private final String packageName;
    private final String appDir;
    private final boolean is64Bit;

    ApkLibraryFile(BaseVM baseVM, Apk apk, String soName, byte[] soData, String packageName, boolean is64Bit) {
        this.baseVM = baseVM;
        this.apk = apk;
        this.soName = soName;
        this.soData = soData;
        this.packageName = packageName;
        this.appDir = packageName == null ? "" : ('/' + packageName + "-1");
        this.is64Bit = is64Bit;
    }

    @Override
    public long getFileSize() {
        return soData.length;
    }

    @Override
    public String getName() {
        return soName;
    }

    @Override
    public String getMapRegionName() {
        return getPath();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
        byte[] libData = baseVM.loadLibraryData(apk, soName);
        return libData == null ? null : new ApkLibraryFile(baseVM, this.apk, soName, libData, packageName, is64Bit);
    }

    @Override
    public ByteBuffer mapBuffer() {
        return ByteBuffer.wrap(soData);
    }

    @Override
    public String getPath() {
        return "/data/app" + appDir + "/lib/" + (is64Bit ? "arm64/" : "arm/") + soName;
    }
}
