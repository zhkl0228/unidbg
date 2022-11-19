package com.github.unidbg.ios;

import com.github.unidbg.spi.LibraryFile;

public interface DarwinLibraryFile extends LibraryFile {

    String resolveBootstrapPath();

}
