package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Utils;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.List;

public class URLibraryFile implements LibraryFile {

    private final URL url;
    private final String path;
    private final String version;
    private final List<String> excludeLibs;

    public URLibraryFile(URL url, String path, String version, List<String> excludeLibs) {
        this.url = url;
        this.path = path;
        this.version = version;
        this.excludeLibs = excludeLibs;
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
    public LibraryFile resolveLibrary(Emulator<?> emulator, String dylibName) {
        if (version == null) {
            return null;
        }
        return DarwinResolver.resolveLibrary(dylibName, version, excludeLibs);
    }

    @Override
    public ByteBuffer mapBuffer() throws IOException {
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            return Utils.mapBuffer(new File(url.getPath()));
        } else {
            return ByteBuffer.wrap(IOUtils.toByteArray(url));
        }
    }

    @Override
    public String getPath() {
        return path;
    }

}
