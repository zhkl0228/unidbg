package com.github.unidbg.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.linux.file.Stdin;
import com.github.unidbg.linux.file.Stdout;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;

public abstract class BaseFileSystem implements FileSystem {

    private static final Log log = LogFactory.getLog(BaseFileSystem.class);

    protected final Emulator emulator;
    protected final File rootDir;

    public BaseFileSystem(Emulator emulator, File rootDir) {
        this.emulator = emulator;
        this.rootDir = rootDir;

        try {
            initialize(this.rootDir);
        } catch (IOException e) {
            throw new IllegalStateException("initialize file system failed", e);
        }
    }

    protected void initialize(File rootDir) throws IOException {
        FileUtils.forceMkdir(new File(rootDir, "tmp"));
    }

    @Override
    public FileResult open(String pathname, int oflags) {
        if (IO.STDIN.equals(pathname)) {
            return FileResult.success(new Stdin(oflags));
        }

        if (IO.STDOUT.equals(pathname) || IO.STDERR.equals(pathname)) {
            try {
                File stdio = new File(rootDir, pathname + ".txt");
                if (!stdio.exists() && !stdio.createNewFile()) {
                    throw new IOException("create new file failed: " + stdio);
                }
                return FileResult.success(new Stdout(oflags, stdio, pathname, IO.STDERR.equals(pathname), null)); // TODO support callback
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        File file = new File(rootDir, pathname);
        return createFileIO(file, oflags, pathname);
    }

    private FileResult createFileIO(File file, int oflags, String path) {
        boolean directory = hasDirectory(oflags);
        if (file.isFile() && directory) {
            return FileResult.failed(UnixEmulator.ENOTDIR);
        }

        boolean create = hasCreat(oflags);
        if (file.exists()) {
            if (create) {
                return FileResult.failed(UnixEmulator.EEXIST);
            }
            return file.isDirectory() ? createDirectoryFileIO(file, oflags, path) : createSimpleFileIO(file, oflags, path);
        }

        if (!create || !file.getParentFile().exists()) {
            return FileResult.failed(UnixEmulator.ENOENT);
        }

        try {
            if (directory) {
                if (!file.mkdir()) {
                    throw new IllegalStateException("mkdir failed: " + file);
                }
                return createDirectoryFileIO(file, oflags, path);
            } else {
                if (!file.createNewFile()) {
                    throw new IllegalStateException("createNewFile failed: " + file);
                }
                return createSimpleFileIO(file, oflags, path);
            }
        } catch (IOException e) {
            throw new IllegalStateException("createNewFile failed: " + file, e);
        }
    }

    @Override
    public boolean mkdir(String path) {
        File dir = new File(rootDir, path);
        if (dir.exists()) {
            return false;
        } else {
            return dir.mkdirs();
        }
    }

    protected FileResult createSimpleFileIO(File file, int oflags, String path) {
        return FileResult.success(new SimpleFileIO(oflags, file, path));
    }

    protected FileResult createDirectoryFileIO(File file, int oflags, String path) {
        return FileResult.success(new DirectoryFileIO(oflags, path, file));
    }

    protected abstract boolean hasCreat(int oflags);
    protected abstract boolean hasDirectory(int oflags);
    protected abstract boolean hasAppend(int oflags);

    @Override
    public void unlink(String path) {
        File file = new File(rootDir, path);
        FileUtils.deleteQuietly(file);
        if (log.isDebugEnabled()) {
            log.debug("unlink path=" + path + ", file=" + file);
        }
    }

    @Override
    public File getRootDir() {
        return rootDir;
    }

    @Override
    public File createWorkDir() {
        File workDir = new File(rootDir, DEFAULT_WORK_DIR);
        if (!workDir.exists() && !workDir.mkdirs()) {
            throw new IllegalStateException("mkdirs failed: " + workDir);
        }
        return workDir;
    }

}
