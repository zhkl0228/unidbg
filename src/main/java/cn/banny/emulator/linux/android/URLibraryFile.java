package cn.banny.emulator.linux.android;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.spi.LibraryFile;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.net.URL;

public class URLibraryFile implements LibraryFile {

    private final URL url;
    private final String name;
    private final int sdk;

    public URLibraryFile(URL url, String name, int sdk) {
        this.url = url;
        this.name = name;
        this.sdk = sdk;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getMapRegionName() {
        return "/system/lib/" + getName();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator emulator, String soName) {
        if (sdk <= 0) {
            return null;
        }
        return AndroidResolver.resolveLibrary(emulator, soName, sdk);
    }

    @Override
    public byte[] readToByteArray() throws IOException {
        return IOUtils.toByteArray(url);
    }

    @Override
    public String getPath() {
        return "/system/lib";
    }
}
