package com.github.unidbg.linux.file;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.Utils;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.IO;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.file.Files;

public class SimpleFileIO extends BaseAndroidFileIO implements NewFileIO {

    private static final Logger log = LoggerFactory.getLogger(SimpleFileIO.class);

    protected final File file;
    protected final String path;
    private RandomAccessFile _randomAccessFile;

    private synchronized RandomAccessFile checkOpenFile() {
        try {
            if (_randomAccessFile == null) {
                FileUtils.forceMkdir(file.getParentFile());
                if (!file.exists() && !file.createNewFile()) {
                    throw new IOException("createNewFile failed: " + file);
                }
                _randomAccessFile = new RandomAccessFile(file, "rws");
                onFileOpened(_randomAccessFile);
            }
            return _randomAccessFile;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public SimpleFileIO(int oflags, File file, String path) {
        super(oflags);
        this.file = file;
        this.path = path;

        if (file.isDirectory()) {
            throw new IllegalArgumentException("file is directory: " + file);
        }
        if (!file.exists()) {
            throw new IllegalArgumentException("file not exists: " + file);
        }
    }

    void onFileOpened(RandomAccessFile randomAccessFile) throws IOException {
    }

    @Override
    public void close() {
        IOUtils.close(_randomAccessFile);

        if (debugStream != null) {
            try {
                debugStream.flush();
            } catch (IOException ignored) {
            }
        }
    }

    @Override
    public int write(byte[] data) {
        try {
            if (debugStream != null) {
                debugStream.write(data);
                debugStream.flush();
            }

            if (log.isDebugEnabled() && data.length < 0x3000) {
                Inspector.inspect(data, "write");
            }

            RandomAccessFile randomAccessFile = checkOpenFile();
            if ((oflags & IOConstants.O_APPEND) != 0) {
                randomAccessFile.seek(randomAccessFile.length());
            }
            randomAccessFile.write(data);
            return data.length;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    OutputStream debugStream;

    void setDebugStream(OutputStream stream) {
        this.debugStream = new BufferedOutputStream(stream);
    }

    @Override
    public int read(Backend backend, Pointer pointer, final int _count) {
        RandomAccessFile randomAccessFile = checkOpenFile();
        return Utils.readFile(randomAccessFile, pointer, _count);
    }

    @Override
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        int st_mode;
        if (IO.STDOUT.equals(file.getName())) {
            st_mode = IO.S_IFCHR | 0x777;
        } else if(Files.isSymbolicLink(file.toPath())) {
            st_mode = IO.S_IFLNK;
        } else {
            st_mode = IO.S_IFREG;
        }
        stat.st_dev = 1;
        stat.st_mode = st_mode;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = file.length();
        stat.st_blksize = emulator.getPageAlign();
        stat.st_ino = 1;
        stat.st_blocks = ((file.length() + emulator.getPageAlign() - 1) / emulator.getPageAlign());
        stat.setLastModification(file.lastModified());
        stat.pack();
        return 0;
    }

    private static final class MmapBuffer extends ByteArrayOutputStream {
        MmapBuffer() {
        }

        MmapBuffer(int capacity) {
            super(capacity);
        }

        void readFrom(RandomAccessFile file, int length) throws IOException {
            byte[] overflow = null;
            while (true) {
                int remaining = length - count;
                if (remaining == 0) {
                    return;
                }
                int available = buf.length - count;
                if (available > 0) {
                    // Limit per-read native scratch while filling the owned result buffer.
                    int read = file.read(buf, count, Math.min(remaining, Math.min(available, 64 * 1024)));
                    if (read == -1) {
                        return;
                    }
                    count += read;
                } else {
                    // Preserve growth when the file changes after its initial length query.
                    if (overflow == null) {
                        overflow = new byte[1024];
                    }
                    int read = file.read(overflow, 0, Math.min(remaining, overflow.length));
                    if (read == -1) {
                        return;
                    }
                    write(overflow, 0, read);
                }
            }
        }

        byte[] finish() {
            // This one-shot buffer is never retained or reused after return.
            return count == buf.length ? buf : toByteArray();
        }
    }

    @Override
    protected byte[] getMmapData(long addr, int offset, int length) throws IOException {
        RandomAccessFile randomAccessFile = checkOpenFile();
        randomAccessFile.seek(offset);
        int remaining = (int) (randomAccessFile.length() - randomAccessFile.getFilePointer());
        MmapBuffer baos = remaining <= 0 ? new MmapBuffer() : new MmapBuffer(Math.min(length, remaining));
        baos.readFrom(randomAccessFile, length);
        return baos.finish();
    }

    @Override
    public String toString() {
        return path;
    }

    @Override
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        if (IO.STDOUT.equals(path) || IO.STDERR.equals(path)) {
            return 0;
        }

        return super.ioctl(emulator, request, argp);
    }

    @Override
    public FileIO dup2() {
        SimpleFileIO dup = new SimpleFileIO(oflags, file, path);
        dup.debugStream = debugStream;
        dup.op = op;
        dup.oflags = oflags;
        return dup;
    }

    @Override
    public int lseek(int offset, int whence) {
        try {
            RandomAccessFile randomAccessFile = checkOpenFile();
            switch (whence) {
                case SEEK_SET:
                    randomAccessFile.seek(offset);
                    return (int) randomAccessFile.getFilePointer();
                case SEEK_CUR:
                    randomAccessFile.seek(randomAccessFile.getFilePointer() + offset);
                    return (int) randomAccessFile.getFilePointer();
                case SEEK_END:
                    randomAccessFile.seek(randomAccessFile.length() + offset);
                    return (int) randomAccessFile.getFilePointer();
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return super.lseek(offset, whence);
    }

    @Override
    public int llseek(long offset, Pointer result, int whence) {
        try {
            RandomAccessFile randomAccessFile = checkOpenFile();
            switch (whence) {
                case SEEK_SET:
                    randomAccessFile.seek(offset);
                    result.setLong(0, randomAccessFile.getFilePointer());
                    return 0;
                case SEEK_END:
                    randomAccessFile.seek(randomAccessFile.length() - offset);
                    result.setLong(0, randomAccessFile.getFilePointer());
                    return 0;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return super.llseek(offset, result, whence);
    }

    @Override
    public int ftruncate(int length) {
        try (FileChannel channel = new FileOutputStream(file, true).getChannel()) {
            channel.truncate(length);
            return 0;
        } catch (IOException e) {
            log.debug("ftruncate failed", e);
            return -1;
        }
    }

    @Override
    public String getPath() {
        return path;
    }
}
