package com.github.unidbg.ios.file;

import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.StdoutCallback;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;

public class Stdout extends SimpleFileIO {

    private static final Log log = LogFactory.getLog(Stdout.class);

    private final boolean err;
    private final PrintStream out;
    private final StdoutCallback callback;

    public Stdout(int oflags, File file, String path, boolean err, StdoutCallback callback) {
        super(oflags, file, path);
        this.callback = callback;

        this.err = err;
        out = err ? System.err : System.out;

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
            out.write(data);
            out.flush();
            if (callback != null) {
                callback.notifyOut(data, err);
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
                case FileIO.SEEK_SET:
                    output.seek(offset);
                    return (int) output.getFilePointer();
                case FileIO.SEEK_CUR:
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
        Stdout dup = new Stdout(0, file, path, err, callback);
        dup.debugStream = debugStream;
        dup.op = op;
        dup.oflags = oflags;
        return dup;
    }
}
