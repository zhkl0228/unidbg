package cn.banny.emulator.linux.file;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class Stdout extends SimpleFileIO {

    private static final Log log = LogFactory.getLog(Stdout.class);

    private final boolean err;

    public Stdout(int oflags, File file, String path, boolean err) {
        super(oflags, file, path);

        this.err = err;

        if (log.isDebugEnabled()) {
            setDebugStream(err ? System.err : System.out);
        }
    }

    @Override
    public void close() {
        super.close();

        IOUtils.closeQuietly(output);
    }

    private RandomAccessFile output;

    @Override
    public int write(byte[] data) {
        try {
            if (output == null) {
                output = new RandomAccessFile(file, "rw");
                output.getChannel().truncate(0);
            }

            if (debugStream != null) {
                debugStream.write(data);
            }

            output.write(data);
            return data.length;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int lseek(int offset, int whence) {
        try {
            switch (whence) {
                case SEEK_SET:
                    output.seek(offset);
                    return (int) output.getFilePointer();
                case SEEK_CUR:
                    output.seek(output.getFilePointer() + offset);
                    return (int) output.getFilePointer();
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return super.lseek(offset, whence);
    }

    @Override
    public int ftruncate(int length) {
        try {
            output.getChannel().truncate(length);
            return 0;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public FileIO dup2() {
        Stdout dup = new Stdout(0, file, path, err);
        dup.debugStream = debugStream;
        dup.op = op;
        dup.oflags = oflags;
        return dup;
    }
}
