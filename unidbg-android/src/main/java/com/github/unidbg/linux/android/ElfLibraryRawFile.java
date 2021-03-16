package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.LibraryFile;

import java.nio.ByteBuffer;

public class ElfLibraryRawFile implements LibraryFile {

    private final ByteBuffer raw;
    private final String name;

    public ElfLibraryRawFile(String name, ByteBuffer buffer) {
        this.raw = buffer;
        this.name = name == null || name.isEmpty() ? String.format("%x.so", buffer.hashCode()) : name;
    }

    public ElfLibraryRawFile(String name, byte[] binary) {
        this(name, ByteBuffer.wrap(binary));
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
