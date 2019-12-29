package cn.banny.unidbg.file;

import cn.banny.unidbg.Emulator;

import java.io.File;

public interface IOResolver {

    FileIO resolve(Emulator emulator, File workDir, String pathname, int oflags);

}
