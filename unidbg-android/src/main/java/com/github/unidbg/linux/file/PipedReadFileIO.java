package com.github.unidbg.linux.file;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PipedInputStream;
import java.util.Arrays;

public class PipedReadFileIO extends BaseAndroidFileIO implements AndroidFileIO {

    private static final Logger log = LoggerFactory.getLogger(PipedReadFileIO.class);

    private final int writefd;
    private final PipedInputStream inputStream;

    public PipedReadFileIO(PipedInputStream inputStream, int writefd) {
        super(IOConstants.O_RDONLY);
        this.inputStream = inputStream;
        this.writefd = writefd;
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        try {
            byte[] receiveBuf = new byte[Math.min(count, inputStream.available())];
            int read = inputStream.read(receiveBuf, 0, receiveBuf.length);
            if (read <= 0) {
                return read;
            }

            byte[] data = Arrays.copyOf(receiveBuf, read);
            buffer.write(0, data, 0, data.length);
            if (log.isDebugEnabled()) {
                log.debug(Inspector.inspectString(data, "read fd=" + writefd));
            }
            return data.length;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean canRead() {
        try {
            return inputStream.available() > 0;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        try {
            inputStream.close();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String toString() {
        return "PipedRead: " + writefd;
    }
}
