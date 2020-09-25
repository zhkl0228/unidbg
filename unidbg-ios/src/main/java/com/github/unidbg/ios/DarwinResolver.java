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
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.ResourceUtils;
import org.apache.commons.io.FilenameUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DarwinResolver implements LibraryResolver, IOResolver<DarwinFileIO> {

    static final String LIB_VERSION = "7.1";

    private final String version;

    private final List<String> excludeLibs = new ArrayList<>();

    public DarwinResolver(String... excludeLibs) {
        this(LIB_VERSION, excludeLibs);
    }

    private DarwinResolver(String version, String... excludeLibs) {
        this.version = version;

        Collections.addAll(this.excludeLibs, excludeLibs);
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName) {
        return resolveLibrary(libraryName, version, excludeLibs);
    }

    private static final Pattern SYSTEM_LIBRARY_FRAMEWORK_PATTERN = Pattern.compile("/System/Library/Frameworks/(\\w+).framework/Versions/[A-C]/(\\w+)");

    static LibraryFile resolveLibrary(String libraryName, String version, List<String> excludeLibs) {
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

        String name = "/ios/" + version + libraryName.replace('+', 'p');
        URL url = DarwinResolver.class.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, version, excludeLibs);
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
        File file = ResourceUtils.extractResource(DarwinResolver.class, iosResource, path);
        if (file != null) {
            return FileResult.fallback(createFileIO(file, path, oflags));
        }

        return null;
    }

    private byte[] _GlobalPreferences;

    private DarwinFileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname, file) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

}
