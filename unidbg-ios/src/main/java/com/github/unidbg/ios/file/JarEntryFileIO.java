package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.ios.BaseDarwinFileIO;
import com.github.unidbg.file.ios.StatStructure;
import com.github.unidbg.unix.IO;
import com.sun.jna.Pointer;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarEntryFileIO extends BaseDarwinFileIO {

    private final String path;
    private final File jarFile;
    private final JarEntry entry;

    public JarEntryFileIO(int oflags, String path, File jarFile, JarEntry entry) {
        super(oflags);
        this.path = path;
        this.jarFile = jarFile;
        this.entry = entry;
    }

    private int pos;
    private JarFile openedJarFile;

    @Override
    public void close() {
        pos = 0;
        if (openedJarFile != null) {
            com.alibaba.fastjson.util.IOUtils.close(openedJarFile);
            openedJarFile = null;
        }
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        try {
            if (pos >= entry.getSize()) {
                return 0;
            }

            if (openedJarFile == null) {
                openedJarFile = new JarFile(this.jarFile);
            }

            int remain = (int) entry.getSize() - pos;
            if (count > remain) {
                count = remain;
            }
            try (InputStream inputStream = openedJarFile.getInputStream(entry)) {
                if (inputStream.skip(pos) != pos) {
                    throw new IllegalStateException();
                }
                buffer.write(0, IOUtils.toByteArray(inputStream, count), 0, count);
            }
            pos += count;
            return count;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int write(byte[] data) {
        throw new UnsupportedOperationException();
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
                pos = (int) entry.getSize() + offset;
                return pos;
        }
        return super.lseek(offset, whence);
    }

    @Override
    protected byte[] getMmapData(long addr, int offset, int length) {
        try (JarFile jarFile = new JarFile(this.jarFile); InputStream inputStream = jarFile.getInputStream(entry)) {
            if (offset == 0 && length == entry.getSize()) {
                return IOUtils.toByteArray(inputStream);
            } else {
                if (inputStream.skip(offset) != offset) {
                    throw new IllegalStateException();
                }
                return IOUtils.toByteArray(inputStream, length);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
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
        stat.setSize(entry.getSize());
        stat.setBlockCount(entry.getSize() / blockSize);
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
