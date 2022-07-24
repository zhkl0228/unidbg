package com.github.unidbg.ios;

import com.dd.plist.NSDictionary;
import com.dd.plist.PropertyListParser;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.ByteArrayFileIO;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.file.SimpleFileIO;
import com.github.unidbg.ios.patch.LibDispatchPatcher;
import com.github.unidbg.ios.patch.NewObjcPatcher;
import com.github.unidbg.ios.patch.OldObjcPatcher;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.ResourceUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DarwinResolver implements LibraryResolver, IOResolver<DarwinFileIO> {

    private static final String LIB_VERSION = "7.1";
    private static final String OVERRIDE_VERSION = "override";

    private final String version;

    private final List<String> excludeLibs = new ArrayList<>();

    public DarwinResolver(String... excludeLibs) {
        this(LIB_VERSION, excludeLibs);
    }

    private DarwinResolver(String version, String... excludeLibs) {
        this.version = version;

        Collections.addAll(this.excludeLibs, excludeLibs);
    }

    private boolean override;

    public DarwinResolver setOverride() {
        this.override = true;
        return this;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName) {
        return resolveLibrary(libraryName, getClass());
    }

    private static final Pattern SYSTEM_LIBRARY_FRAMEWORK_PATTERN = Pattern.compile("/System/Library/Frameworks/(\\w+).framework/Versions/[A-C]/(\\w+)");

    LibraryFile resolveLibrary(String libraryName, Class<?> resClass) {
        if (!excludeLibs.isEmpty() && excludeLibs.contains(FilenameUtils.getName(libraryName))) {
            return null;
        }

        Matcher systemLibraryFrameworkMatcher = SYSTEM_LIBRARY_FRAMEWORK_PATTERN.matcher(libraryName);
        if (systemLibraryFrameworkMatcher.find()) {
            String f1 = systemLibraryFrameworkMatcher.group(1);
            String f2 = systemLibraryFrameworkMatcher.group(2);
            if (f1.equals(f2)) {
                libraryName = "/System/Library/Frameworks/" + f1 + ".framework/" + f1;
            }
        }

        if (override) {
            String name = "/ios/" + OVERRIDE_VERSION + libraryName.replace('+', 'p');
            URL url = resClass.getResource(name);
            if (url != null) {
                return new URLibraryFile(url, libraryName, this);
            }
        }

        String name = "/ios/" + version + libraryName.replace('+', 'p');
        URL url = resClass.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, this);
        }
        return null;
    }

    @Override
    public FileResult<DarwinFileIO> resolve(Emulator<DarwinFileIO> emulator, String path, int oflags) {
        if ("".equals(path)) {
            return FileResult.failed(UnixEmulator.ENOENT);
        }

        FileSystem<DarwinFileIO> fileSystem = emulator.getFileSystem();
        if (".".equals(path)) {
            return FileResult.success(createFileIO(fileSystem.createWorkDir(), path, oflags));
        }

        if (path.endsWith("/Library/Preferences/.GlobalPreferences.plist")) {
            if (_GlobalPreferences == null) {
                Locale locale = Locale.getDefault();
                Map<String, Object> map = new HashMap<>();
                map.put("AppleICUForce24HourTime", true);
                map.put("AppleLanguages", new String[] { locale.getLanguage() });
                map.put("AppleLocale", locale.toString());
                NSDictionary root = (NSDictionary) NSDictionary.fromJavaObject(map);
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                try {
                    PropertyListParser.saveAsBinary(root, outputStream);
                } catch (IOException e) {
                    throw new IllegalStateException("save .GlobalPreferences.plist failed", e);
                }
                _GlobalPreferences = outputStream.toByteArray();
            }
            return FileResult.<DarwinFileIO>success(new ByteArrayFileIO(oflags, path, _GlobalPreferences));
        }

        String iosResource = FilenameUtils.normalize("/ios/" + version + "/" + path, true);
        URL url = getClass().getResource(iosResource);
        if (url != null) {
            return FileResult.fallback(createFileIO(url, path, oflags));
        }

        return null;
    }

    private DarwinFileIO createFileIO(URL url, String pathname, int oflags) {
        File file = ResourceUtils.toFile(url);
        if (file != null) {
            return createFileIO(file, pathname, oflags);
        }

        try {
            URLConnection connection = url.openConnection();
            try (InputStream inputStream = connection.getInputStream()) {
                if (connection instanceof JarURLConnection) {
                    JarURLConnection jarURLConnection = (JarURLConnection) connection;
                    JarFile jarFile = jarURLConnection.getJarFile();
                    JarEntry entry = jarURLConnection.getJarEntry();
                    if (entry.isDirectory()) {
                        Enumeration<JarEntry> entryEnumeration = jarFile.entries();
                        List<DirectoryFileIO.DirectoryEntry> list = new ArrayList<>();
                        while (entryEnumeration.hasMoreElements()) {
                            JarEntry check = entryEnumeration.nextElement();
                            if (entry.getName().equals(check.getName())) {
                                continue;
                            }
                            if (check.getName().startsWith(entry.getName())) {
                                boolean isDir = check.isDirectory();
                                String sub = check.getName().substring(entry.getName().length());
                                if (isDir) {
                                    sub = sub.substring(0, sub.length() - 1);
                                }
                                if (!sub.contains("/")) {
                                    list.add(new DirectoryFileIO.DirectoryEntry(true, sub));
                                }
                            }
                        }
                        return new DirectoryFileIO(oflags, pathname, null, list.toArray(new DirectoryFileIO.DirectoryEntry[0]));
                    } else {
                        byte[] data = IOUtils.toByteArray(inputStream);
                        return new ByteArrayFileIO(oflags, pathname, data);
                    }
                } else {
                    throw new IllegalStateException(connection.getClass().getName());
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException(pathname, e);
        }
    }

    private byte[] _GlobalPreferences;

    private DarwinFileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname, file) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

    @Override
    public void onSetToLoader(Emulator<?> emulator) {
        Memory memory = emulator.getMemory();
        memory.addModuleListener(new LibDispatchPatcher());
        if (override) {
            memory.addModuleListener(new NewObjcPatcher());
        } else {
            memory.addHookListener(new OldObjcPatcher());
        }
    }

}
