package com.github.unidbg.file;

import java.io.File;

public interface FileSystem {

    File getRootDir();
    File createWorkDir(); // 当设置了rootDir以后才可用，为rootDir/unidbg_work目录

    FileIO open(String pathname, int oflags);
    void unlink(String path);

}
