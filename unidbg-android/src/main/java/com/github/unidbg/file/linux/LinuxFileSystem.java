package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileSystem;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.linux.android.LogCatHandler;
import com.github.unidbg.linux.file.*;
import com.github.unidbg.unix.IO;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class LinuxFileSystem extends BaseFileSystem<AndroidFileIO> implements FileSystem<AndroidFileIO>, IOConstants {

    public LinuxFileSystem(Emulator<AndroidFileIO> emulator, File rootDir) {
        super(emulator, rootDir);
    }

    @Override
    public FileResult<AndroidFileIO> open(String pathname, int oflags) {
        if ("/dev/tty".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new NullFileIO(pathname));
        }
        if ("/proc/self/maps".equals(pathname) || ("/proc/" + emulator.getPid() + "/maps").equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new MapsFileIO(oflags, pathname, emulator.getMemory().getLoadedModules()));
        }

        return super.open(pathname, oflags);
    }

    public LogCatHandler getLogCatHandler() {
        return null;
    }

    @Override
    protected void initialize(File rootDir) throws IOException {
        super.initialize(rootDir);

        FileUtils.forceMkdir(new File(rootDir, "system"));
        FileUtils.forceMkdir(new File(rootDir, "data"));
    }

    @Override
    public AndroidFileIO createSimpleFileIO(File file, int oflags, String path) {
        return new SimpleFileIO(oflags, file, path);
    }

    @Override
    public AndroidFileIO createDirectoryFileIO(File file, int oflags, String path) {
        return new DirectoryFileIO(oflags, path, file);
    }

    @Override
    protected AndroidFileIO createStdin(int oflags) {
        return new Stdin(oflags);
    }

    @Override
    protected AndroidFileIO createStdout(int oflags, File stdio, String pathname) {
        return new Stdout(oflags, stdio, pathname, IO.STDERR.equals(pathname), null);
    }

    @Override
    protected boolean hasCreat(int oflags) {
        return (oflags & O_CREAT) != 0;
    }

    @Override
    protected boolean hasDirectory(int oflags) {
        return (oflags & O_DIRECTORY) != 0;
    }

    @Override
    protected boolean hasAppend(int oflags) {
        return (oflags & O_APPEND) != 0;
    }

    @Override
    protected boolean hasExcl(int oflags) {
        return (oflags & O_EXCL) != 0;
    }
}
