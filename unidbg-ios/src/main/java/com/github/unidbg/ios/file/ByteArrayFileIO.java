package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.unix.IO;
import com.sun.jna.Pointer;

public class ByteArrayFileIO extends BaseDarwinFileIO {

    private final byte[] bytes;
    private final String path;

    public ByteArrayFileIO(int oflags, String path, byte[] bytes) {
        super(oflags);
        this.path = path;
        this.bytes = bytes;
    }

    private int pos;

    @Override
    public void close() {
        pos = 0;
    }

    @Override
    public int write(byte[] data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        if (pos >= bytes.length) {
            return 0;
        }

        int remain = bytes.length - pos;
        if (count > remain) {
            count = remain;
        }
        buffer.write(0, bytes, pos, count);
        pos += count;
        return count;
    }

    @Override
    public int lseek(int offset, int whence) {
        switch (whence) {
            case SEEK_SET:
                pos = offset;
                return pos;
            case SEEK_CUR:
                pos += offset;
                return pos;
            case SEEK_END:
                pos = bytes.length + offset;
                return pos;
        }
        return super.lseek(offset, whence);
    }

    @Override
    protected byte[] getMmapData(int offset, int length) {
        if (offset == 0 && length == bytes.length) {
            return bytes;
        } else {
            byte[] data = new byte[length];
            System.arraycopy(bytes, offset, data, 0, data.length);
            return data;
        }
    }

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        return 0;
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        int blockSize = emulator.getPageAlign();
        stat.st_dev = 1;
        stat.st_mode = (short) (IO.S_IFREG | 0x777);
        stat.setSize(bytes.length);
        stat.setBlockCount(bytes.length / blockSize);
        stat.st_blksize = blockSize;
        stat.st_ino = 7;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.setLastModification(System.currentTimeMillis());
        stat.pack();
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }

    @Override
    public String getPath() {
        return path;
    }

}
