package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.ByteArrayFileIO;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

class IpaResolver implements IOResolver<DarwinFileIO> {

    private static final Log log = LogFactory.getLog(IpaResolver.class);

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

        pathname = FilenameUtils.normalize(pathname);
        if (pathname.startsWith(appDir)) {
            String path = "Payload" + pathname.substring(randomDir.length());
            try (JarFile jarFile = new JarFile(ipa)) {
                Enumeration<JarEntry> enumeration = jarFile.entries();
                JarEntry entry = null;
                while (enumeration.hasMoreElements()) {
                    JarEntry jarEntry = enumeration.nextElement();
                    if (path.equals(jarEntry.getName()) || (path + "/").equals(jarEntry.getName())) {
                        entry = jarEntry;
                        break;
                    }
                }
                if (entry == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resolve appDir=" + appDir + ", path=" + path);
                    }
                    return null;
                }

                if (entry.isDirectory()) {
                    System.err.println("Resolve appDir=" + appDir + ", path=" + path + ", entry=" + entry);
                } else {
                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
                        return FileResult.<DarwinFileIO>success(new ByteArrayFileIO(oflags, pathname, IOUtils.toByteArray(inputStream)));
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        return null;
    }

}
