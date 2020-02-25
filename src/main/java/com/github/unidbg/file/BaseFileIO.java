package com.github.unidbg.file;

public abstract class BaseFileIO extends AbstractFileIO implements NewFileIO {

    public BaseFileIO(int oflags) {
        super(oflags);
    }

}
