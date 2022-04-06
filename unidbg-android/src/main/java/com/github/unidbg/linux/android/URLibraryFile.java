package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.Utils;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;

public class URLibraryFile implements LibraryFile {

    private final URL url;
    private final String name;
    private final int sdk;
    private final boolean is64Bit;

    public URLibraryFile(URL url, String name, int sdk, boolean is64Bit) {
        this.url = url;
        this.name = name;
        this.sdk = sdk;
        this.is64Bit = is64Bit;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getMapRegionName() {
        return getPath();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
        if (sdk <= 0) {
            return null;
        }
        return AndroidResolver.resolveLibrary(emulator, soName, sdk);
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
        return "/system/" + (is64Bit ? "lib64/" : "lib/") + name;
    }
}
