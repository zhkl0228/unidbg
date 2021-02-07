package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.linux.LinuxFileSystem;
import com.github.unidbg.linux.android.LogCatHandler;
import com.github.unidbg.linux.android.LogCatLevel;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

public class LogCatFileIO extends SimpleFileIO {

    private static final Log log = LogFactory.getLog(LogCatFileIO.class);

    public static final String LOG_PATH_PREFIX = "/dev/log/";

    private final Emulator<?> emulator;
    private final String type;

    public LogCatFileIO(Emulator<?> emulator, int oflags, File file, String path) {
        super(oflags, file, path);
        this.emulator = emulator;
        this.type = path.substring(LOG_PATH_PREFIX.length());

        if (log.isDebugEnabled()) {
            setDebugStream(System.out);
        }
    }

    @Override
    void onFileOpened(RandomAccessFile randomAccessFile) throws IOException {
        super.onFileOpened(randomAccessFile);

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
                LogCatLevel value = LogCatLevel.valueOf(level);
                super.write(String.format("%s/%s: %s\n", value, tag, text).getBytes());

                LinuxFileSystem fileSystem = (LinuxFileSystem) emulator.getFileSystem();
                LogCatHandler handler = fileSystem.getLogCatHandler();
                if (handler != null) {
                    handler.handleLog(type, value, tag, text);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return data.length;
    }

}
