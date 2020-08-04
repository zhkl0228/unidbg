package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.LogCatFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.utils.ResourceUtils;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

public class AndroidResolver implements LibraryResolver, IOResolver<AndroidFileIO> {

    private final int sdk;
    private final List<String> needed;

    public AndroidResolver(int sdk, String... needed) {
        this.sdk = sdk;
        this.needed = needed == null ? null : Arrays.asList(needed);
    }

    public int getSdk() {
        return sdk;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName) {
        if (needed == null) {
            return null;
        }

        if (!needed.isEmpty() && !needed.contains(libraryName)) {
            return null;
        }

        return resolveLibrary(emulator, libraryName, sdk);
    }

    static LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName, int sdk) {
        final String lib = emulator.is32Bit() ? "lib" : "lib64";
        String name = "/android/sdk" + sdk + "/" + lib + "/" + libraryName.replace('+', 'p');
        URL url = AndroidResolver.class.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, sdk);
        }
        return null;
    }

    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String path, int oflags) {
        FileSystem<AndroidFileIO> fileSystem = emulator.getFileSystem();
        File rootDir = fileSystem.getRootDir();
        if (path.startsWith(LogCatFileIO.LOG_PATH_PREFIX)) {
            try {
                File log = new File(rootDir, path);
                File logDir = log.getParentFile();
                if (!logDir.exists() && !logDir.mkdirs()) {
                    throw new IOException("mkdirs failed: " + logDir);
                }
                if (!log.exists() && !log.createNewFile()) {
                    throw new IOException("create new file failed: " + log);
                }
                return FileResult.<AndroidFileIO>success(new LogCatFileIO(emulator, oflags, log, path));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        if (".".equals(path)) {
            return FileResult.success(createFileIO(fileSystem.createWorkDir(), path, oflags));
        }

        String androidResource = FilenameUtils.normalize("/android/sdk" + sdk + "/" + path, true);
        File file = ResourceUtils.extractResource(AndroidResolver.class, androidResource, path);
        if (file != null) {
            return FileResult.fallback(createFileIO(file, path, oflags));
        }

        return null;
    }

    private AndroidFileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

}
