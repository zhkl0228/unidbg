package com.github.unidbg.ios.ipa;

import com.github.unidbg.Emulator;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class IpaLibraryFile implements LibraryFile {

    private static final Log log = LogFactory.getLog(IpaLibraryFile.class);

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
    public String getName() {
        return executable;
    }

    @Override
    public String getMapRegionName() {
        return executable;
    }

    @Override
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) throws IOException {
        if (!soName.contains("@")) {
            return null;
        }

        String path = soName.replace("@executable_path/", appDir);
        if (log.isDebugEnabled()) {
            log.debug("Try resolve library soName=" + soName + ", path=" + path);
        }
        if (path.contains("@")) {
            log.warn("Try resolve library soName=" + soName + ", path=" + path);
            return null;
        }
        if (!loadList.isEmpty() && !loadList.contains(FilenameUtils.getName(path))) {
            return null;
        }
        byte[] libData = IpaLoader.loadZip(ipa, path);
        return libData == null ? null : new IpaLibraryFile(appDir, ipa, soName, bundleAppDir, libData, loadList);
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
