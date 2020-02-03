package com.github.unidbg.linux.file;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class LogCatFileIO extends SimpleFileIO {

    private static final Log log = LogFactory.getLog(LogCatFileIO.class);

    /**
     * Priority constant for the println method; use Log.v.
     */
    static final int VERBOSE = 2;

    /**
     * Priority constant for the println method; use Log.d.
     */
    static final int DEBUG = 3;

    /**
     * Priority constant for the println method; use Log.i.
     */
    static final int INFO = 4;

    /**
     * Priority constant for the println method; use Log.w.
     */
    static final int WARN = 5;

    /**
     * Priority constant for the println method; use Log.e.
     */
    static final int ERROR = 6;

    /**
     * Priority constant for the println method.
     */
    static final int ASSERT = 7;

    public LogCatFileIO(int oflags, File file, String path) {
        super(oflags, file, path);

        if (log.isDebugEnabled()) {
            setDebugStream(System.out);
        }
    }

    @Override
    void onCreate(RandomAccessFile randomAccessFile) throws IOException {
        super.onCreate(randomAccessFile);

        randomAccessFile.getChannel().truncate(0);
    }

    private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

    @Override
    public int write(byte[] data) {
        try {
            byteArrayOutputStream.write(data);

            if (byteArrayOutputStream.size() <= 1) {
                return data.length;
            }

            int tagIndex = -1;
            int bodyIndex = -1;
            byte[] body = byteArrayOutputStream.toByteArray();
            for (int i = 1; i < body.length; i++) {
                if (body[i] != 0) {
                    continue;
                }

                if (tagIndex == -1) {
                    tagIndex = i;
                    continue;
                }

                bodyIndex = i;
                break;
            }

            if (tagIndex != -1 && bodyIndex != -1) {
                byteArrayOutputStream.reset();

                int level = body[0] & 0xff;
                String tag = new String(body, 1, tagIndex - 1);
                String text = new String(body, tagIndex + 1, bodyIndex - tagIndex - 1);
                final String c;
                switch (level) {
                    case VERBOSE:
                        c = "V";
                        break;
                    case DEBUG:
                        c = "D";
                        break;
                    case INFO:
                        c = "I";
                        break;
                    case WARN:
                        c = "W";
                        break;
                    case ERROR:
                        c = "E";
                        break;
                    case ASSERT:
                        c = "A";
                        break;
                    default:
                        c = level + "";
                        break;
                }
                super.write(String.format("%s/%s: %s\n", c, tag, text).getBytes());
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return data.length;
    }

}
