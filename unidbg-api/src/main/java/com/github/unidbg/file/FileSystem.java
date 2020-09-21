package com.github.unidbg.file;

import java.io.File;

public interface FileSystem<T extends NewFileIO> {

    String DEFAULT_ROOT_FS = "rootfs/default";
    String DEFAULT_WORK_DIR = "unidbg_work";

    File getRootDir();
    File createWorkDir(); // 当设置了rootDir以后才可用，为rootDir/unidbg_work目录

    FileResult<T> open(String pathname, int oflags);
    void unlink(String path);

    /**
     * @return <code>true</code>表示创建成功
     */
    boolean mkdir(String path);

    void rmdir(String path);

    T createSimpleFileIO(File file, int oflags, String path);

    T createDirectoryFileIO(File file, int oflags, String path);

    int rename(String oldPath, String newPath);
}
