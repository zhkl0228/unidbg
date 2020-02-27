package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.sun.jna.Pointer;

public abstract class BaseAndroidFileIO extends BaseFileIO implements AndroidFileIO {

    public BaseAndroidFileIO(int oflags) {
        super(oflags);
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int getdents64(Pointer dirp, int size) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public AndroidFileIO accept(Pointer addr, Pointer addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }
}
