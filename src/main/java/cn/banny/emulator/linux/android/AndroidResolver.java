package cn.banny.emulator.linux.android;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryFile;
import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.linux.IO;
import cn.banny.emulator.linux.file.*;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

public class AndroidResolver implements LibraryResolver, IOResolver {

    private final int sdk;
    private final List<String> needed;

    public AndroidResolver(int sdk, String... needed) {
        this.sdk = sdk;
        this.needed = needed == null ? null : Arrays.asList(needed);
    }

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String libraryName) {
        if (needed == null) {
            return null;
        }

        if (!needed.isEmpty() && !needed.contains(libraryName)) {
            return null;
        }

        return resolveLibrary(emulator, libraryName, sdk);
    }

    static LibraryFile resolveLibrary(Emulator emulator, String libraryName, int sdk) {
        final String lib = emulator.getPointerSize() == 4 ? "lib" : "lib64";
        String name = "/android/sdk" + sdk + "/" + lib + "/" + libraryName.replace('+', 'p');
        URL url = AndroidResolver.class.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, sdk);
        }
        return null;
    }

    @Override
    public FileIO resolve(File workDir, String path, int oflags) {
        if (workDir == null) {
            workDir = new File("target");
        }

        final boolean create = (oflags & FileIO.O_CREAT) != 0;

        if (IO.STDOUT.equals(path) || IO.STDERR.equals(path)) {
            try {
                if (!workDir.exists() && !workDir.mkdir()) {
                    throw new IOException("mkdir failed: " + workDir);
                }
                File stdio = new File(workDir, path);
                if (!stdio.exists() && !stdio.createNewFile()) {
                    throw new IOException("create new file failed: " + stdio);
                }
                return new Stdout(oflags, stdio, path, IO.STDERR.equals(path));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        if (path.startsWith("/dev/log/")) {
            try {
                File log = new File(workDir, path);
                File logDir = log.getParentFile();
                if (!logDir.exists() && !logDir.mkdirs()) {
                    throw new IOException("mkdirs failed: " + logDir);
                }
                if (!log.exists() && !log.createNewFile()) {
                    throw new IOException("create new file failed: " + log);
                }
                return new LogCatFileIO(oflags, log, path);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        if (".".equals(path)) {
            return createFileIO(workDir, path, oflags);
        }

        File file;
        if (path.startsWith(workDir.getAbsolutePath()) && ((file = new File(path)).canRead() || create)) {
            if (file.canRead()) {
                return createFileIO(file, path, oflags);
            }
            try {
                if (!file.exists() && !file.createNewFile()) {
                    throw new IOException("create file failed: " + file);
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
            return createFileIO(file, path, oflags);
        }

        file = new File(workDir, path);
        if (file.canRead()) {
            return createFileIO(file, path, oflags);
        }
        if (file.getParentFile().exists() && create) {
            return createFileIO(file, path, oflags);
        }

        String androidResource = FilenameUtils.normalize("/android/sdk" + sdk + "/" + path, true);
        InputStream inputStream = AndroidResolver.class.getResourceAsStream(androidResource);
        if (inputStream != null) {
            OutputStream outputStream = null;
            try {
                File tmp = new File(FileUtils.getTempDirectory(), path);
                File dir = tmp.getParentFile();
                if (!dir.exists() && !dir.mkdirs()) {
                    throw new IOException("mkdirs failed: " + dir);
                }
                if (!tmp.exists() && !tmp.createNewFile()) {
                    throw new IOException("createNewFile failed: " + tmp);
                }
                outputStream = new FileOutputStream(tmp);
                IOUtils.copy(inputStream, outputStream);
                return createFileIO(tmp, path, oflags);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } finally {
                IOUtils.closeQuietly(outputStream);
                IOUtils.closeQuietly(inputStream);
            }
        } else if ("/dev/__properties__".equals(path)) {
            return new DirectoryFileIO(oflags, path);
        }

        return null;
    }

    private FileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

}
