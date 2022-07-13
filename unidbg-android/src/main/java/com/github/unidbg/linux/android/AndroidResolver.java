package com.github.unidbg.linux.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.InlineHook;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.LogCatFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.linux.thread.ThreadJoin19;
import com.github.unidbg.linux.thread.ThreadJoin23;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.ThreadJoinVisitor;
import com.github.unidbg.utils.ResourceUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class AndroidResolver implements LibraryResolver, IOResolver<AndroidFileIO> {

    private final int sdk;
    private final List<String> needed;

    public AndroidResolver(int sdk, String... needed) {
        this.sdk = sdk;
        this.needed = needed == null ? null : Arrays.asList(needed);
    }

    public void patchThread(Emulator<?> emulator, InlineHook inlineHook, ThreadJoinVisitor visitor) {
        switch (sdk) {
            case 19:
                ThreadJoin19.patch(emulator, inlineHook, visitor);
                break;
            case 23:
                ThreadJoin23.patch(emulator, inlineHook, visitor);
                break;
            default:
                throw new UnsupportedOperationException();
        }
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

        return resolveLibrary(emulator, libraryName, sdk, getClass());
    }

    static LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName, int sdk) {
        return resolveLibrary(emulator, libraryName, sdk, AndroidResolver.class);
    }

    protected static LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName, int sdk, Class<?> resClass) {
        final String lib = emulator.is32Bit() ? "lib" : "lib64";
        String name = "/android/sdk" + sdk + "/" + lib + "/" + libraryName.replace('+', 'p');
        URL url = resClass.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, sdk, emulator.is64Bit());
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
        URL url = getClass().getResource(androidResource);
        if (url != null) {
            return FileResult.fallback(createFileIO(url, path, oflags));
        }

        return null;
    }

    private AndroidFileIO createFileIO(URL url, String pathname, int oflags) {
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
                        return new DirectoryFileIO(oflags, pathname, list.toArray(new DirectoryFileIO.DirectoryEntry[0]));
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

    private AndroidFileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

    @Override
    public void onSetToLoader(Emulator<?> emulator) {
        AndroidEmulator androidEmulator = (AndroidEmulator) emulator;
        SyscallHandler<AndroidFileIO> syscallHandler = androidEmulator.getSyscallHandler();
        syscallHandler.addIOResolver(this);
    }

}
