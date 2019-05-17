package cn.banny.unidbg.linux.file;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.file.AbstractFileIO;
import cn.banny.unidbg.file.FileIO;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.io.IOException;
import java.util.Arrays;

public class NullFileIO extends AbstractFileIO implements FileIO {

    private final String path;

    public NullFileIO(String path) {
        super(O_RDWR);

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
    public int read(Unicorn unicorn, Pointer buffer, int count) {
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
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        stat.setLong(0x30, 0); // st_size
        stat.setInt(0x38, 0); // st_blksize
        return 0;
    }

    @Override
    public FileIO dup2() {
        throw new AbstractMethodError();
    }

    @Override
    public int ioctl(Emulator emulator, long request, long argp) {
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }
}
