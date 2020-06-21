package com.github.unidbg.file;

import java.io.File;

public abstract class BaseFileIO extends AbstractFileIO implements NewFileIO {

    public BaseFileIO(int oflags) {
        super(oflags);
    }

    protected final File createAttrFile(File dest) {
        if (!dest.exists()) {
            throw new IllegalStateException("dest=" + dest);
        }

        File file;
        if (dest.isDirectory()) {
            file = new File(dest, UnidbgFileFilter.UNIDBG_PREFIX + ".json");
        } else {
            file = new File(dest.getParentFile(), UnidbgFileFilter.UNIDBG_PREFIX + "_" + dest.getName() + ".json");
        }
        return file;
    }

}
