package com.github.unidbg.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Arrays;

public class Stdin extends BaseFileIO implements AndroidFileIO, DarwinFileIO {

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
    public int read(Unicorn unicorn, Pointer buffer, int count) {
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
    public int fstat(Emulator<?> emulator, com.github.unidbg.file.linux.StatStructure stat) {
        stat.st_mode = 0x0;
        stat.st_size = 0;
        stat.pack();
        return 0;
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
    public int getdents64(Pointer dirp, int size) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
        return "stdin";
    }
}
