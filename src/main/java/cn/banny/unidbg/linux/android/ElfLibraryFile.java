package cn.banny.unidbg.linux.android;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.spi.LibraryFile;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

public class ElfLibraryFile implements LibraryFile {

    private final File elfFile;

    public ElfLibraryFile(File elfFile) {
        this.elfFile = elfFile;
    }

    @Override
    public String getName() {
        return elfFile.getName();
    }

    @Override
    public String getMapRegionName() {
        return "/system/lib/" + getName();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String soName) {
        File file = new File(elfFile.getParentFile(), soName);
        return file.canRead() ? new ElfLibraryFile(file) : null;
    }

    @Override
    public byte[] readToByteArray() throws IOException {
        return FileUtils.readFileToByteArray(elfFile);
    }

    @Override
    public ByteBuffer mapBuffer() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getPath() {
        return "/system/lib";
    }

}
