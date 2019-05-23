package cn.banny.unidbg.ios;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.spi.LibraryFile;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;

public class URLibraryFile implements LibraryFile {

    private final URL url;
    private final String path;
    private final String version;

    public URLibraryFile(URL url, String path, String version) {
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

    @Override
    public ByteBuffer mapBuffer() throws IOException {
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            return MachOLibraryFile.mapBuffer(new File(url.getPath()));
        } else {
            return ByteBuffer.wrap(readToByteArray());
        }
    }

    @Override
    public String getPath() {
        return "/usr/lib";
    }

}
