package com.github.unidbg.ios.dmg;

import com.github.unidbg.Emulator;
import com.github.unidbg.Utils;
import com.github.unidbg.spi.LibraryFile;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class DmgLibraryFile implements LibraryFile {

    private static final Log log = LogFactory.getLog(DmgLibraryFile.class);

    private final String executable;
    private final File file;
    private final String bundleAppDir;

    DmgLibraryFile(String executable, String bundleAppDir, File file, String... loads) {
        this(executable, bundleAppDir, file, Arrays.asList(loads));
    }

    private final List<String> loadList;

    private DmgLibraryFile(String executable, String bundleAppDir, File file, List<String> loadList) {
        this.executable = executable;
        this.file = file;
        this.bundleAppDir = bundleAppDir;
        this.loadList = loadList;
    }

    @Override
    public long getFileSize() {
        return file.length();
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
    public LibraryFile resolveLibrary(Emulator<?> emulator, String soName) {
        if (!soName.contains("@")) {
            return null;
        }

        String path = soName.replace("@executable_path", file.getParentFile().getPath());
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
        File file = new File(path);
        if (!file.exists() || !file.isFile()) {
            return null;
        } else {
            return new DmgLibraryFile(soName, bundleAppDir, file, loadList);
        }
    }

    @Override
    public ByteBuffer mapBuffer() throws IOException {
        return Utils.mapBuffer(file);
    }

    @Override
    public String getPath() {
        return FilenameUtils.normalize(file.getPath(), true);
    }

}
