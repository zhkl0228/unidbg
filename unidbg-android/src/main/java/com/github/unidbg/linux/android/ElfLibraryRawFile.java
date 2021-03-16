package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class ElfLibraryRawFile implements LibraryFile {
    private final ByteBuffer raw;
    private final String name;

    public ElfLibraryRawFile(String name, ByteBuffer buffer) {
        this.raw = buffer;
        if (name == null || name.isEmpty()) {
            name = String.format("%x.so", buffer.hashCode());
        }
        this.name = name;
    }

    public ElfLibraryRawFile(String name, byte[] binary) {
        this(name, ByteBuffer.wrap(binary));
    }

    public ElfLibraryRawFile(String name, InputStream stream) throws IOException {
        this(name, IOUtils.toByteArray(stream));
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getMapRegionName() {
        return "/system/lib/" + this.getName();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
        return null;
    }

    @Override
    public ByteBuffer mapBuffer() {
        return raw;
    }

    @Override
    public String getPath() {
        return null;
    }
}
