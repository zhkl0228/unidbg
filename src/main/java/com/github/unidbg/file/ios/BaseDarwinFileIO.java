package com.github.unidbg.file.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.github.unidbg.ios.struct.kernel.StatFS;

public abstract class BaseDarwinFileIO extends BaseFileIO implements DarwinFileIO {

    public BaseDarwinFileIO(int oflags) {
        super(oflags);
    }

    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    public int fstatfs(StatFS statFS) {
        throw new UnsupportedOperationException(getClass().getName());
    }

}
