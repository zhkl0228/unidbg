package com.github.unidbg.file;

import com.github.unidbg.Emulator;

public interface IOResolver<T extends NewFileIO> {

    FileResult<T> resolve(Emulator<T> emulator, String pathname, int oflags);

}
