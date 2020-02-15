package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileSystem;
import com.github.unidbg.file.FileSystem;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class DarwinFileSystem extends BaseFileSystem implements FileSystem, IOConstants {

    public DarwinFileSystem(Emulator emulator, File rootDir) {
        super(emulator, rootDir);
    }

    @Override
    protected void initialize(File rootDir) throws IOException {
        super.initialize(rootDir);

        FileUtils.forceMkdir(new File(rootDir, "private"));
        FileUtils.forceMkdir(new File(rootDir, "etc"));
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
}
