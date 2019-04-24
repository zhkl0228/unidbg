package cn.banny.emulator;

import cn.banny.emulator.file.IOResolver;
import cn.banny.emulator.spi.LibraryFile;

public interface LibraryResolver extends IOResolver {

    LibraryFile resolveLibrary(Emulator emulator, String libraryName);

}
