package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;

public class DumpFileIO extends BaseDarwinFileIO implements DarwinFileIO {

    private final int fd;

    public DumpFileIO(int fd) {
        super(0);

        this.fd = fd;
    }

    @Override
    public int write(byte[] data) {
        Inspector.inspect(data, "Dump for fd: " + fd);
        return data.length;
    }

    @Override
    public void close() {
    }

    @Override
    public FileIO dup2() {
        return this;
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int fstatfs(StatFS statFS) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getdirentries64(Pointer buf, int bufSize) {
        throw new UnsupportedOperationException();
    }
}
