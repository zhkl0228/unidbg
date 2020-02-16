package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.ios.IOConstants;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.linux.file.StdoutCallback;
import com.github.unidbg.spi.LibraryFile;
import com.github.unidbg.unix.UnixEmulator;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.URL;

public class DarwinResolver implements LibraryResolver, IOResolver {

    static final String LIB_VERSION = "7.1";

    private final String version;

    public DarwinResolver() {
        this(LIB_VERSION);
    }

    private DarwinResolver(String version) {
        this.version = version;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String libraryName) {
        return resolveLibrary(libraryName, version);
    }

    private StdoutCallback callback;

    @Override
    public void setStdoutCallback(StdoutCallback callback) {
        this.callback = callback;
    }

    static LibraryFile resolveLibrary(String libraryName, String version) {
        String name = "/ios/" + version + libraryName.replace('+', 'p');
        URL url = DarwinResolver.class.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, version);
        }
        return null;
    }

    @Override
    public FileResult resolve(Emulator emulator, String path, int oflags) {
        if ("".equals(path)) {
            return FileResult.failed(UnixEmulator.EINVAL);
        }

        if (".".equals(path)) {
            return createFileIO(emulator.getFileSystem().createWorkDir(), path, oflags);
        }

        final File rootDir = emulator.getFileSystem().getRootDir();
        File file = new File(rootDir, path);
        if (file.canRead()) {
            return createFileIO(file, path, oflags);
        }
        final boolean create = (oflags & IOConstants.O_CREAT) != 0;
        if (file.getParentFile().exists() && create) {
            return createFileIO(file, path, oflags);
        }

        String iosResource = FilenameUtils.normalize("/ios/" + version + "/" + path, true);
        InputStream inputStream = AndroidResolver.class.getResourceAsStream(iosResource);
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
        }

        return null;
    }

    private FileResult createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return FileResult.success(file.isDirectory() ? new DirectoryFileIO(oflags, pathname) : new SimpleFileIO(oflags, file, pathname));
        }

        return null;
    }

}
