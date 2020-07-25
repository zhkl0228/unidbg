package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.github.unidbg.linux.struct.StatFS;
import com.sun.jna.Pointer;

public abstract class BaseAndroidFileIO extends BaseFileIO implements AndroidFileIO {

    public BaseAndroidFileIO(int oflags) {
        super(oflags);
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int getdents64(Pointer dirp, int size) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public AndroidFileIO accept(Pointer addr, Pointer addrlen) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public int statfs(StatFS statFS) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected void setFlags(long arg) {
        if ((IOConstants.O_APPEND & arg) != 0) {
            oflags |= IOConstants.O_APPEND;
        }
        if ((IOConstants.O_RDWR & arg) != 0) {
            oflags |= IOConstants.O_RDWR;
        }
        if ((IOConstants.O_NONBLOCK & arg) != 0) {
            oflags |= IOConstants.O_NONBLOCK;
        }
    }
}
