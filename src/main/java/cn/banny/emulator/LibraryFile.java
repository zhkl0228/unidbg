package cn.banny.emulator;

import java.io.IOException;

public interface LibraryFile {

    String getName();

    String getMapRegionName();

    LibraryFile resolveLibrary(Emulator emulator, String soName) throws IOException;

    byte[] readToByteArray() throws IOException;

}
