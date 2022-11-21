package com.github.unidbg.ios.ipa;

import com.github.unidbg.ios.DarwinLibraryFile;
import com.github.unidbg.ios.MachOLibraryFile;

import java.io.File;

public class BundleLibraryFile extends MachOLibraryFile implements DarwinLibraryFile {

    private final String executableBundleDir;

    BundleLibraryFile(File file, String executableBundleDir) {
        super(file);
        this.executableBundleDir = executableBundleDir;
    }

    @Override
    public String resolveBootstrapPath() {
        return executableBundleDir + "/" + BundleLoader.APP_NAME;
    }

    @Override
    public String getPath() {
        return this.executableBundleDir + "/Frameworks/" + file.getName() + ".framework/" + file.getName();
    }

}
