package cn.banny.emulator.linux.file;

import java.io.File;

public interface IOResolver {

    FileIO resolve(File workDir, String pathname, int oflags);

}
