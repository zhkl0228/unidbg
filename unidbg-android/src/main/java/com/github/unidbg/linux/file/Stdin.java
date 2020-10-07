package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.util.Arrays;

public class Stdin extends BaseAndroidFileIO implements AndroidFileIO {

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
    public int getdents64(Pointer dirp, int size) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String toString() {
        return "stdin";
    }
}
