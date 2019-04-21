package cn.banny.emulator.linux.file;

import cn.banny.emulator.file.FileIO;

import java.io.File;

public interface IOResolver {

    FileIO resolve(File workDir, String pathname, int oflags);

}
