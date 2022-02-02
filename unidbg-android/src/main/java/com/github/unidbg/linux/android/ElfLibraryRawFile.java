package com.github.unidbg.linux.android;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.LibraryFile;

import java.nio.ByteBuffer;

public class ElfLibraryRawFile implements LibraryFile {

    private final ByteBuffer raw;
    private final String name;
    private final boolean is64Bit;

    public ElfLibraryRawFile(String name, ByteBuffer buffer, boolean is64Bit) {
        this.raw = buffer;
        this.name = name == null || name.isEmpty() ? String.format("%x.so", buffer.hashCode()) : name;
        this.is64Bit = is64Bit;
    }

    public ElfLibraryRawFile(String name, byte[] binary, boolean is64Bit) {
        this(name, ByteBuffer.wrap(binary), is64Bit);
    }

    @Override
    public long getFileSize() {
        return raw.capacity();
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
        return null;
    }

    @Override
    public ByteBuffer mapBuffer() {
        return raw;
    }

    @Override
    public String getPath() {
        return "/system/" + (is64Bit ? "lib64/" : "lib/") + name;
    }
}
