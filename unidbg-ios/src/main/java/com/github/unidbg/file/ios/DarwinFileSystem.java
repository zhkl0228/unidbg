package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileSystem;
import com.github.unidbg.file.FileSystem;
import com.github.unidbg.ios.file.DirectoryFileIO;
import com.github.unidbg.ios.file.SimpleFileIO;
import com.github.unidbg.ios.file.Stdin;
import com.github.unidbg.ios.file.Stdout;
import com.github.unidbg.unix.IO;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class DarwinFileSystem extends BaseFileSystem<DarwinFileIO> implements FileSystem<DarwinFileIO>, IOConstants {

    public DarwinFileSystem(Emulator<DarwinFileIO> emulator, File rootDir) {
        super(emulator, rootDir);
    }

    @Override
    protected void initialize(File rootDir) throws IOException {
        super.initialize(rootDir);

        FileUtils.forceMkdir(new File(rootDir, "private"));
    }

    @Override
    public DarwinFileIO createSimpleFileIO(File file, int oflags, String path) {
        return new SimpleFileIO(oflags, file, path);
    }

    @Override
    public DarwinFileIO createDirectoryFileIO(File file, int oflags, String path) {
        return new DirectoryFileIO(oflags, path, file);
    }

    @Override
    protected DarwinFileIO createStdin(int oflags) {
        return new Stdin(oflags);
    }

    @Override
    protected DarwinFileIO createStdout(int oflags, File stdio, String pathname) {
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
