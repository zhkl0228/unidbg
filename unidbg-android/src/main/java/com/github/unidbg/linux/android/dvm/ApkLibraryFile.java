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

    ApkLibraryFile(BaseVM baseVM, Apk apk, String soName, byte[] soData, String packageName) {
        this.baseVM = baseVM;
        this.apk = apk;
        this.soName = soName;
        this.soData = soData;
        this.packageName = packageName;
        this.appDir = packageName == null ? "" : ('/' + packageName + "-1");
    }

    @Override
    public String getName() {
        return soName;
    }

    @Override
    public String getMapRegionName() {
        return "/data/app-lib" + appDir + '/' + soName;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
        byte[] libData = baseVM.loadLibraryData(apk, soName);
        return libData == null ? null : new ApkLibraryFile(baseVM, this.apk, soName, libData, packageName);
    }

    @Override
    public ByteBuffer mapBuffer() {
        return ByteBuffer.wrap(soData);
    }

    @Override
    public String getPath() {
        return "/data/app-lib" + appDir;
    }
}
