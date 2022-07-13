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

public class URLibraryFile implements LibraryFile {

    private final URL url;
    private final String path;
    private final DarwinResolver resolver;

    public URLibraryFile(URL url, String path, DarwinResolver resolver) {
        this.url = url;
        this.path = path;
        this.resolver = resolver;
    }

    @Override
    public String getName() {
        return FilenameUtils.getName(path);
    }

    @Override
    public String getMapRegionName() {
        return getPath();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String dylibName) {
        if (resolver == null) {
            return null;
        }
        return resolver.resolveLibrary(dylibName, resolver.getClass());
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
    public long getFileSize() {
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            return new File(url.getPath()).length();
        } else {
            try {
                return IOUtils.toByteArray(url).length;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @Override
    public String getPath() {
        return path;
    }

}
