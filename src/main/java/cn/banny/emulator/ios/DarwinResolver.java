package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryFile;
import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.file.IOResolver;

import java.io.File;
import java.net.URL;

public class DarwinResolver implements LibraryResolver, IOResolver {

    private final String version;

    public DarwinResolver(String version) {
        this.version = version;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String libraryName) {
        return resolveLibrary(emulator, libraryName, version);
    }

    static LibraryFile resolveLibrary(Emulator emulator, String libraryName, String version) {
        String name = "/ios/" + version + libraryName.replace('+', 'p');
        URL url = DarwinResolver.class.getResource(name);
        if (url != null) {
            return new URLibraryFile(url, libraryName, version);
        }
        return null;
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        return null;
    }

}
