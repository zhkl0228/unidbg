package com.github.unidbg.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public abstract class BaseFileSystem<T extends NewFileIO> implements FileSystem<T> {

    private static final Logger log = LoggerFactory.getLogger(BaseFileSystem.class);

    protected final Emulator<T> emulator;
    protected final File rootDir;

    public BaseFileSystem(Emulator<T> emulator, File rootDir) {
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

    /**
     * Resolves the given guest pathname against rootDir and returns the resulting
     * host {@link File} only when it is strictly contained within rootDir.
     * Path traversal components (e.g. {@code ../}) are neutralised by
     * canonicalization before the containment check is performed.
     *
     * @param pathname guest-controlled path component
     * @return the resolved host {@code File}, or {@code null} when the resolved
     *         path would escape rootDir (traversal attempt)
     */
    protected File resolveFileInRootDir(String pathname) {
        try {
            File candidate = new File(rootDir, pathname);
            String canonicalRoot = rootDir.getCanonicalPath();
            String canonicalCandidate = candidate.getCanonicalPath();
            // Ensure the separator is appended so that a directory whose name is a
            // prefix of another directory is not mistakenly accepted.
            if (!canonicalRoot.endsWith(File.separator)) {
                canonicalRoot = canonicalRoot + File.separator;
            }
            if (canonicalCandidate.equals(canonicalRoot.substring(0, canonicalRoot.length() - 1))
                    || canonicalCandidate.startsWith(canonicalRoot)) {
                return candidate;
            }
            if (log.isDebugEnabled()) {
                log.debug("Path traversal rejected: pathname={}, candidate={}", pathname, canonicalCandidate);
            }
            return null;
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to canonicalize path: pathname={}", pathname, e);
            }
            return null;
        }
    }

    @Override
    public FileResult<T> open(String pathname, int oflags) {
        if ("".equals(pathname)) {
            return FileResult.failed(UnixEmulator.ENOENT); // No such file or directory
        }

        if (IO.STDIN.equals(pathname)) {
            return FileResult.success(createStdin(oflags));
        }

        if (IO.STDOUT.equals(pathname) || IO.STDERR.equals(pathname)) {
            try {
                File stdio = new File(rootDir, pathname + ".txt");
                if (!stdio.exists() && !stdio.createNewFile()) {
                    throw new IOException("create new file failed: " + stdio);
                }
                return FileResult.success(createStdout(oflags, stdio, pathname));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        File file = new File(rootDir, pathname);
        if (resolveFileInRootDir(pathname) == null) {
            return FileResult.failed(UnixEmulator.EACCES);
        }
        return createFileIO(file, oflags, pathname);
    }

    protected abstract T createStdout(int oflags, File stdio, String pathname);

    protected abstract T createStdin(int oflags);

    private FileResult<T> createFileIO(File file, int oflags, String path) {
        boolean directory = hasDirectory(oflags);
        if (file.isFile() && directory) {
            return FileResult.failed(UnixEmulator.ENOTDIR);
        }

        boolean create = hasCreat(oflags);
        if (file.exists()) {
            if (create && hasExcl(oflags)) {
                return FileResult.failed(UnixEmulator.EEXIST);
            }
            return FileResult.success(file.isDirectory() ? createDirectoryFileIO(file, oflags, path) : createSimpleFileIO(file, oflags, path));
        }

        if (!create) {
            return FileResult.failed(UnixEmulator.ENOENT);
        }

        try {
            if (directory) {
                FileUtils.forceMkdir(file);
                return FileResult.success(createDirectoryFileIO(file, oflags, path));
            } else {
                if (!file.getParentFile().exists()) {
                    FileUtils.forceMkdir(file.getParentFile());
                }
                FileUtils.touch(file);
                return FileResult.success(createSimpleFileIO(file, oflags, path));
            }
        } catch (IOException e) {
            throw new IllegalStateException("createNewFile failed: " + file, e);
        }
    }

    @Override
    public boolean mkdir(String path, int mode) {
        File dir = resolveFileInRootDir(path);
        if (emulator.getSyscallHandler().isVerbose()) {
            System.out.printf("mkdir '%s' with mode 0x%x from %s%n", path, mode, emulator.getContext().getLRPointer());
        }

        if (dir == null) {
            return false;
        }
        if (dir.exists()) {
            return true;
        } else {
            return dir.mkdirs();
        }
    }

    @Override
    public void rmdir(String path) {
        File dir = resolveFileInRootDir(path);
        if (dir != null) {
            FileUtils.deleteQuietly(dir);
        }

        if (emulator.getSyscallHandler().isVerbose()) {
            System.out.printf("rmdir '%s' from %s%n", path, emulator.getContext().getLRPointer());
        }
    }

    protected abstract boolean hasCreat(int oflags);
    protected abstract boolean hasDirectory(int oflags);
    @SuppressWarnings("unused")
    protected abstract boolean hasAppend(int oflags);
    protected abstract boolean hasExcl(int oflags);

    @Override
    public void unlink(String path) {
        File file = resolveFileInRootDir(path);
        if (file != null) {
            FileUtils.deleteQuietly(file);
        }
        if (log.isDebugEnabled()) {
            log.debug("unlink path={}", path);
        }
        if (emulator.getSyscallHandler().isVerbose()) {
            System.out.printf("unlink '%s' from %s%n", path, emulator.getContext().getLRPointer());
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

    @Override
    public int rename(String oldPath, String newPath) {
        File oldFile = resolveFileInRootDir(oldPath);
        File newFile = resolveFileInRootDir(newPath);

        if (oldFile == null || newFile == null) {
            return -UnixEmulator.EACCES;
        }

        try {
            FileUtils.forceMkdir(newFile.getParentFile());

            if (oldFile.exists()) {
                Files.move(oldFile.toPath(), newFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }

            if (emulator.getSyscallHandler().isVerbose()) {
                System.out.printf("rename '%s' to '%s' from %s%n", oldPath, newPath, emulator.getContext().getLRPointer());
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return 0;
    }
}
