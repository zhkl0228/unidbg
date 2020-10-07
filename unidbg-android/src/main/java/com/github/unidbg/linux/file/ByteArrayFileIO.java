package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.IO;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;

public class ByteArrayFileIO extends BaseAndroidFileIO {

    private static final Log log = LogFactory.getLog(ByteArrayFileIO.class);

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
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(Arrays.copyOfRange(bytes, pos, pos + count), "read path=" + path + ", fp=" + pos + ", _count=" + count + ", length=" + bytes.length + ", buffer=" + buffer));
        }
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
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        stat.st_dev = 1;
        stat.st_mode = IO.S_IFREG;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = bytes.length;
        stat.st_blksize = emulator.getPageAlign();
        stat.st_blocks = ((bytes.length + emulator.getPageAlign() - 1) / emulator.getPageAlign());
        stat.st_ino = 1;
        stat.setLastModification(System.currentTimeMillis());
        stat.pack();
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
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        return 0;
    }

    @Override
    public String toString() {
        return path;
    }

}
