package cn.banny.emulator;

import cn.banny.emulator.file.IOResolver;

public interface LibraryResolver extends IOResolver {

    LibraryFile resolveLibrary(Emulator emulator, String libraryName);

}
