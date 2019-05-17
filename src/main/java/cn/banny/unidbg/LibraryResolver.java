package cn.banny.unidbg;

import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.spi.LibraryFile;

public interface LibraryResolver extends IOResolver {

    LibraryFile resolveLibrary(Emulator emulator, String libraryName);

}
