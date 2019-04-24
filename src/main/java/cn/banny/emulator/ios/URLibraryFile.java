package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.spi.LibraryFile;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.URL;

public class URLibraryFile implements LibraryFile {

    private final URL url;
    private final String path;
    private final String version;

    URLibraryFile(URL url, String path, String version) {
        this.url = url;
        this.path = path;
        this.version = version;
    }

    @Override
    public String getName() {
        return FilenameUtils.getName(path);
    }

    @Override
    public String getMapRegionName() {
        return path;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String dylibName) {
        if (version == null) {
            return null;
        }
        return DarwinResolver.resolveLibrary(dylibName, version);
    }

    @Override
    public byte[] readToByteArray() throws IOException {
        return IOUtils.toByteArray(url);
    }
}
