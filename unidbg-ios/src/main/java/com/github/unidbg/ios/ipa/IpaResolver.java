package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.ByteArrayFileIO;
import com.github.unidbg.ios.file.DirectoryFileIO;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

class IpaResolver implements IOResolver<DarwinFileIO> {

    private static final Log log = LogFactory.getLog(IpaResolver.class);

    private final String appDir;
    private final File ipa;
    private final String randomDir;

    IpaResolver(String appDir, File ipa) {
        this.appDir = FilenameUtils.normalize(appDir, true);
        this.ipa = ipa;
        this.randomDir = FilenameUtils.normalize(new File(appDir).getParentFile().getPath(), true);
    }

    @Override
    public FileResult<DarwinFileIO> resolve(Emulator<DarwinFileIO> emulator, String pathname, int oflags) {
        if ((randomDir + "/StoreKit/receipt").equals(pathname)) {
            return FileResult.<DarwinFileIO>success(new ByteArrayFileIO(oflags, pathname, new byte[0]));
        }

        pathname = FilenameUtils.normalize(pathname, true);
        if (pathname.startsWith(appDir)) {
            String path = IpaLoader.PAYLOAD_PREFIX + pathname.substring(randomDir.length());
            try (JarFile jarFile = new JarFile(ipa)) {
                Enumeration<JarEntry> enumeration = jarFile.entries();
                JarEntry entry = null;
                boolean hasChild = false;
                String dir = path;
                if (!dir.endsWith("/")) {
                    dir += "/";
                }
                while (enumeration.hasMoreElements()) {
                    JarEntry jarEntry = enumeration.nextElement();
                    if (path.equals(jarEntry.getName()) || (path + "/").equals(jarEntry.getName())) {
                        entry = jarEntry;
                        break;
                    }
                    if (!hasChild && jarEntry.getName().startsWith(dir)) {
                        hasChild = true;
                    }
                }
                if (entry == null && hasChild) {
                    return FileResult.success(createDirectoryFileIO(dir, pathname, oflags));
                }

                if (entry == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Resolve appDir=" + appDir + ", path=" + path);
                    }
                    return null;
                }

                if (entry.isDirectory()) {
                    return FileResult.success(createDirectoryFileIO(entry.getName(), pathname, oflags));
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

    private DarwinFileIO createDirectoryFileIO(String dirEntry, String pathname, int oflags) throws IOException {
        List<DirectoryFileIO.DirectoryEntry> list = new ArrayList<>();
        try (JarFile jarFile = new JarFile(ipa)) {
            Enumeration<JarEntry> enumeration = jarFile.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (entry.getName().startsWith(dirEntry)) {
                    String subName = entry.getName().substring(dirEntry.length());
                    int index = subName.indexOf('/');
                    if (index == -1) { // file
                        list.add(new DirectoryFileIO.DirectoryEntry(true, subName));
                    } else if(subName.indexOf('/', index + 1) == -1) { // dir
                        list.add(new DirectoryFileIO.DirectoryEntry(false, subName.substring(0, index)));
                    }
                }
            }
        }
        return new DirectoryFileIO(oflags, pathname, ipa.getParentFile(), list.toArray(new DirectoryFileIO.DirectoryEntry[0]));
    }

}
