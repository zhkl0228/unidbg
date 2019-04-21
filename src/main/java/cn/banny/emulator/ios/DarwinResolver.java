package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryFile;
import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.linux.file.IOResolver;

import java.io.File;

public class DarwinResolver implements LibraryResolver, IOResolver {

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String libraryName) {
        return null;
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        return null;
    }

}
