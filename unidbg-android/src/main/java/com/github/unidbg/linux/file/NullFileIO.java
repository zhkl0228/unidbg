package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.file.linux.StatStructure;
import com.sun.jna.Pointer;

import java.io.IOException;
import java.util.Arrays;

public class NullFileIO extends BaseAndroidFileIO implements FileIO {

    private final String path;

    public NullFileIO(String path) {
        super(IOConstants.O_RDWR);

        this.path = path;
    }

    private boolean isTTY() {
        return "/dev/tty".equals(path);
    }

    @Override
    public void close() {
    }

    @Override
    public int write(byte[] data) {
        if (isTTY()) {
            try {
                System.out.write(data);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        return data.length;
    }

    @Override
    public int lseek(int offset, int whence) {
        return 0;
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        if (isTTY()) {
            try {
                byte[] buf = new byte[count];
                int read = System.in.read(buf);
                if (read <= 0) {
                    return read;
                }
                buffer.write(0, Arrays.copyOf(buf, read), 0, read);
                return read;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return 0;
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        stat.st_size = 0;
        stat.st_blksize = 0;
        stat.pack();
        return 0;
    }

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }
}
