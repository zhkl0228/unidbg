package com.github.unidbg.file;

import java.io.File;
import java.io.FileFilter;

public class UnidbgFileFilter implements FileFilter {

    public static final String UNIDBG_PREFIX = "__ignore.unidbg";

    @Override
    public boolean accept(File pathname) {
        return !pathname.getName().startsWith(UNIDBG_PREFIX);
    }

}
