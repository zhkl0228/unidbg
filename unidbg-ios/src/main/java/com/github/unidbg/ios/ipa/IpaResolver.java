package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.ByteArrayFileIO;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.file.JarEntryFileIO;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

class IpaResolver implements IOResolver<DarwinFileIO> {

    private static final Logger log = LoggerFactory.getLogger(IpaResolver.class);

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
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, new byte[0]));
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
                        log.debug("Resolve appDir={}, path={}", appDir, path);
                    }
                    return null;
                }

                if (entry.isDirectory()) {
                    return FileResult.success(createDirectoryFileIO(entry.getName(), pathname, oflags));
                } else {
                    return FileResult.success(new JarEntryFileIO(oflags, pathname, ipa, entry));
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        return null;
    }

    private DarwinFileIO createDirectoryFileIO(String dirEntry, String pathname, int oflags) throws IOException {
        List<DirectoryFileIO.DirectoryEntry> list = new ArrayList<>();
        list.add(new DirectoryFileIO.DirectoryEntry(false, "."));
        list.add(new DirectoryFileIO.DirectoryEntry(false, ".."));
        Set<String> dirSet = new HashSet<>();
        try (JarFile jarFile = new JarFile(ipa)) {
            Enumeration<JarEntry> enumeration = jarFile.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                if (entry.getName().startsWith(dirEntry)) {
                    String subName = entry.getName().substring(dirEntry.length());
                    if (subName.isEmpty()) {
                        continue;
                    }
                    int index = subName.indexOf('/');
                    if (index == -1) { // file
                        list.add(new DirectoryFileIO.DirectoryEntry(true, subName));
                    } else {
                        int endIndex = subName.indexOf('/', index + 1);
                        if (endIndex == -1 || endIndex == subName.length() - 1) { // dir
                            String dir = subName.substring(0, index);
                            if (dirSet.add(dir)) {
                                list.add(new DirectoryFileIO.DirectoryEntry(false, dir));
                            }
                        }
                    }
                }
            }
        }
        return new DirectoryFileIO(oflags, pathname, ipa.getParentFile(), list.toArray(new DirectoryFileIO.DirectoryEntry[0]));
    }

}
