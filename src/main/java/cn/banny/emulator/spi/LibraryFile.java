package cn.banny.emulator.spi;

import cn.banny.emulator.Emulator;

import java.io.IOException;

public interface LibraryFile {

    String getName();

    String getMapRegionName();

    LibraryFile resolveLibrary(Emulator emulator, String soName) throws IOException;

    byte[] readToByteArray() throws IOException;

    String getPath();

}
