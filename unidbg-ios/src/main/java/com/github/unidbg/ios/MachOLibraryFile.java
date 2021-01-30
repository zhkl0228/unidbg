package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Utils;
import com.github.unidbg.spi.LibraryFile;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

public class MachOLibraryFile implements LibraryFile {

    private final File file;

    MachOLibraryFile(File file) {
        this.file = file;
    }

    @Override
    public String getName() {
        return file.getName();
    }

    @Override
    public String getMapRegionName() {
        return "/usr/lib/" + getName();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
        File file = new File(this.file.getParentFile(), soName);
        return file.canRead() ? new MachOLibraryFile(file) : null;
    }

    @Override
    public ByteBuffer mapBuffer() throws IOException {
        return Utils.mapBuffer(file);
    }

    @Override
    public String getPath() {
        return "/usr/lib";
    }

}
