package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.util.Arrays;

public class Stdin extends BaseDarwinFileIO implements DarwinFileIO {

    public Stdin(int oflags) {
        super(oflags);
    }

    @Override
    public void close() {
    }

    @Override
    public int write(byte[] data) {
        throw new AbstractMethodError(new String(data));
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        try {
            byte[] data = new byte[count];
            int read = System.in.read(data, 0, count);
            if (read <= 0) {
                return read;
            }

            buffer.write(0, Arrays.copyOf(data, read), 0, read);
            return read;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public FileIO dup2() {
        return this;
    }

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        return 0;
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
    public String toString() {
        return "stdin";
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
