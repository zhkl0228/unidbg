package com.github.unidbg.linux.android.dvm.apk;

import java.io.File;

public class ApkFactory {

    public static Apk createApk(File file) {
        return file.isDirectory() ? new ApkDir(file) : new ApkFile(file);
    }

}
