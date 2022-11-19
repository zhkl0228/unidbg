package com.github.unidbg.ios.ipa;

import com.github.unidbg.ios.DarwinLibraryFile;
import com.github.unidbg.ios.MachOLibraryFile;

import java.io.File;

public class BundleLibraryFile extends MachOLibraryFile implements DarwinLibraryFile {

    public static final String APP_NAME = "UniDbg";

    private final String executableBundlePath;

    BundleLibraryFile(File file, String executableBundlePath) {
        super(file);
        this.executableBundlePath = executableBundlePath;
    }

    @Override
    public String resolveBootstrapPath() {
        return executableBundlePath + "/" + APP_NAME;
    }

    @Override
    public String getPath() {
        return this.executableBundlePath + "/Frameworks/" + file.getName() + ".framework/" + file.getName();
    }

}
