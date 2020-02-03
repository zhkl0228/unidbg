package com.github.unidbg.file;

import com.github.unidbg.Emulator;

import java.io.File;

public interface IOResolver {

    FileIO resolve(Emulator emulator, File workDir, String pathname, int oflags);

}
