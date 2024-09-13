package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class IpaLibraryFile implements LibraryFile {

    private static final Logger log = LoggerFactory.getLogger(IpaLibraryFile.class);

    private final String appDir;
    private final File ipa;
    private final String executable;
    private final byte[] data;
    private final String bundleAppDir;

    IpaLibraryFile(String appDir, File ipa, String executable, String bundleAppDir, String... loads) throws IOException {
        this(appDir, ipa, executable, bundleAppDir, IpaLoader.loadZip(ipa, appDir + executable), Arrays.asList(loads));
    }

    private final List<String> loadList;

    private IpaLibraryFile(String appDir, File ipa, String executable, String bundleAppDir, byte[] data, List<String> loadList) {
        this.appDir = appDir;
        this.ipa = ipa;
        this.executable = executable;
        this.data = data;
        this.bundleAppDir = bundleAppDir;
        this.loadList = loadList;
    }

    @Override
    public long getFileSize() {
        return data.length;
    }

    @Override
    public String getName() {
        return executable;
    }

    @Override
    public String getMapRegionName() {
        return getPath();
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) throws IOException {
        if (!soName.contains("@")) {
            return null;
        }

        String path = soName.replace("@executable_path/", appDir);
        if (log.isDebugEnabled()) {
            log.debug("Try resolve library soName={}, path={}", soName, path);
        }
        if (path.contains("@")) {
            log.warn("Try resolve library soName={}, path={}", soName, path, new Exception());
            return null;
        }
        if (!loadList.isEmpty() && !loadList.contains(FilenameUtils.getName(path))) {
            return null;
        }
        byte[] libData = IpaLoader.loadZip(ipa, path);
        if (libData != null) {
            return new IpaLibraryFile(appDir, ipa, soName, bundleAppDir, libData, loadList);
        } else {
            return null;
        }
    }

    @Override
    public ByteBuffer mapBuffer() {
        return ByteBuffer.wrap(data);
    }

    @Override
    public String getPath() {
        return appDir.replace(IpaLoader.PAYLOAD_PREFIX, bundleAppDir) + executable;
    }

}
