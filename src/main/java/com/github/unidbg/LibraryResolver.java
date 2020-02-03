package com.github.unidbg;

import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.file.StdoutCallback;
import com.github.unidbg.spi.LibraryFile;

public interface LibraryResolver extends IOResolver {

    LibraryFile resolveLibrary(Emulator emulator, String libraryName);

    void setStdoutCallback(StdoutCallback callback);

}
