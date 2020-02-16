package com.github.unidbg.file;

import com.github.unidbg.Emulator;

public interface IOResolver {

    FileResult resolve(Emulator emulator, String pathname, int oflags);

}
