package com.github.unidbg;

import com.github.unidbg.spi.LibraryFile;

public interface LibraryResolver {

    LibraryFile resolveLibrary(Emulator<?> emulator, String libraryName);

}
