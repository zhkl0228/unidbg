package com.github.unidbg.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;

public class DumpFileIO extends BaseFileIO implements AndroidFileIO, DarwinFileIO {

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
    public int fstat(Emulator<?> emulator, com.github.unidbg.file.linux.StatStructure stat) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getdents64(Pointer dirp, int size) {
        throw new UnsupportedOperationException();
    }
}
