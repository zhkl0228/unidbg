package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;

public abstract class BaseAndroidFileIO extends BaseFileIO implements AndroidFileIO {

    public BaseAndroidFileIO(int oflags) {
        super(oflags);
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new AbstractMethodError(getClass().getName());
    }

}
