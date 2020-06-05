package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.file.SimpleFileIO;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.ResourceUtils;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

    static LibraryFile resolveLibrary(String libraryName, String version, List<String> excludeLibs) {
        if (!excludeLibs.isEmpty() && excludeLibs.contains(FilenameUtils.getName(libraryName))) {
            return null;
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

        String iosResource = FilenameUtils.normalize("/ios/" + version + "/" + path, true);
        File file = ResourceUtils.extractResource(iosResource, path);
        if (file != null) {
            return FileResult.fallback(createFileIO(file, path, oflags));
        }

        return null;
    }

    private DarwinFileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname, file) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

}
