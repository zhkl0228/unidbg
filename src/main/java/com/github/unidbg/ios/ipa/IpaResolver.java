package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.ByteArrayFileIO;

import java.io.File;

class IpaResolver implements IOResolver<DarwinFileIO> {

    private final String appDir;
    private final File ipa;
    private final String randomDir;

    IpaResolver(String appDir, File ipa) {
        this.appDir = appDir;
        this.ipa = ipa;
        this.randomDir = new File(appDir).getParentFile().getAbsolutePath();
    }

    @Override
    public FileResult<DarwinFileIO> resolve(Emulator<DarwinFileIO> emulator, String pathname, int oflags) {
        if ((randomDir + "/StoreKit/receipt").equals(pathname)) {
            return FileResult.<DarwinFileIO>success(new ByteArrayFileIO(oflags, pathname, new byte[0]));
        }

        if (pathname.startsWith("/var/containers/Bundle/Application/")) {
            System.err.println("Resolve appDir=" + appDir + ", path=" + pathname);
        }
        return null;
    }

}
