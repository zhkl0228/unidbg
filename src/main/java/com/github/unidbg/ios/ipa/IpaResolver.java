package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;

import java.io.File;

class IpaResolver implements IOResolver<DarwinFileIO> {

    private final String appDir;
    private final File ipa;

    IpaResolver(String appDir, File ipa) {
        this.appDir = appDir;
        this.ipa = ipa;
    }

    @Override
    public FileResult<DarwinFileIO> resolve(Emulator<DarwinFileIO> emulator, String pathname, int oflags) {
        System.err.println("Resolve appDir=" + appDir + ", path=" + pathname);
        return null;
    }

}
