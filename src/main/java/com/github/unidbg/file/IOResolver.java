package com.github.unidbg.file;

import com.github.unidbg.Emulator;

public interface IOResolver {

    FileIO resolve(Emulator emulator, String pathname, int oflags);

}
