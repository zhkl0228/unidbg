package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.file.AbstractFileIO;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

public class ByteArrayFileIO extends AbstractFileIO {

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
    public int read(Unicorn unicorn, Pointer buffer, int count) {
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
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        stat.setLong(0x30, bytes.length); // st_size
        stat.setInt(0x38, (int) ARM.alignSize(bytes.length, emulator.getPageAlign())); // st_blksize
        return 0;
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
    public int ioctl(Emulator emulator, long request, long argp) {
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }

}
