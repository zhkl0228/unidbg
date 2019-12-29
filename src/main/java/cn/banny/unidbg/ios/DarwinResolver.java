package cn.banny.unidbg.ios;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.unix.IO;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.file.DirectoryFileIO;
import cn.banny.unidbg.linux.file.SimpleFileIO;
import cn.banny.unidbg.linux.file.Stdout;
import cn.banny.unidbg.spi.LibraryFile;
import cn.banny.unidbg.LibraryResolver;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
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

    static LibraryFile resolveLibrary(String libraryName, String version) {
        String name = "/ios/" + version + libraryName.replace('+', 'p');
        URL url = DarwinResolver.class.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, version);
        }
        return null;
    }

    @Override
    public FileIO resolve(Emulator emulator, File workDir, String path, int oflags) {
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

    private FileIO createFileIO(File file, String pathname, int oflags) {
        if (file.canRead()) {
            return file.isDirectory() ? new DirectoryFileIO(oflags, pathname) : new SimpleFileIO(oflags, file, pathname);
        }

        return null;
    }

}
