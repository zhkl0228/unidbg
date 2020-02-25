package com.github.unidbg.file.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.BaseFileIO;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

public abstract class BaseAndroidFileIO extends BaseFileIO implements AndroidFileIO {

    public BaseAndroidFileIO(int oflags) {
        super(oflags);
    }

    @Override
    public int fstat(Emulator<?> emulator, Unicorn unicorn, Pointer stat) {
        throw new AbstractMethodError(getClass().getName());
    }

}
