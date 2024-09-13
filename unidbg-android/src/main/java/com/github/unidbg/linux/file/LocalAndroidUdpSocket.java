package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.LinuxFileSystem;
import com.github.unidbg.linux.android.LogCatHandler;
import com.github.unidbg.linux.android.LogCatLevel;
import com.github.unidbg.unix.UnixEmulator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class LocalAndroidUdpSocket extends LocalUdpSocket implements AndroidFileIO {

    private static final Logger log = LoggerFactory.getLogger(LocalAndroidUdpSocket.class);

    public LocalAndroidUdpSocket(Emulator<?> emulator) {
        super(emulator);
    }

    @Override
    protected int connect(String path) {
        if ("/dev/socket/logdw".equals(path)) {
            handler = new UdpHandler() {
                private static final int LOG_ID_MAIN = 0;
                private static final int LOG_ID_RADIO = 1;
                private static final int LOG_ID_EVENTS = 2;
                private static final int LOG_ID_SYSTEM = 3;
                private static final int LOG_ID_CRASH = 4;
                private static final int LOG_ID_KERNEL = 5;
                private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

                @Override
                public void handle(byte[] request) {
                    try {
                        byteArrayOutputStream.write(request);

                        if (byteArrayOutputStream.size() <= 11) {
                            return;
                        }

                        int tagIndex = -1;
                        int bodyIndex = -1;
                        byte[] body = byteArrayOutputStream.toByteArray();
                        ByteBuffer buffer = ByteBuffer.wrap(body);
                        buffer.order(ByteOrder.LITTLE_ENDIAN);
                        int id = buffer.get() & 0xff;
                        int tid = buffer.getShort() & 0xffff;
                        int tv_sec = buffer.getInt();
                        int tv_nsec = buffer.getInt();
                        if (log.isDebugEnabled()) {
                            log.debug("handle id={}, tid={}, tv_sec={}, tv_nsec={}", id, tid, tv_sec, tv_nsec);
                        }

                        String type;
                        switch (id) {
                            case LOG_ID_MAIN:
                                type = "main";
                                break;
                            case LOG_ID_RADIO:
                                type = "radio";
                                break;
                            case LOG_ID_EVENTS:
                                type = "events";
                                break;
                            case LOG_ID_SYSTEM:
                                type = "system";
                                break;
                            case LOG_ID_CRASH:
                                type = "crash";
                                break;
                            case LOG_ID_KERNEL:
                                type = "kernel";
                                break;
                            default:
                                type = Integer.toString(id);
                                break;
                        }

                        for (int i = 12; i < body.length; i++) {
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

                            int value = body[11] & 0xff;
                            String tag = new String(body, 12, tagIndex - 12);
                            String text = new String(body, tagIndex + 1, bodyIndex - tagIndex - 1);
                            LogCatLevel level = LogCatLevel.valueOf(value);

                            LinuxFileSystem fileSystem = (LinuxFileSystem) emulator.getFileSystem();
                            LogCatHandler handler = fileSystem.getLogCatHandler();
                            if (handler != null) {
                                handler.handleLog(type, level, tag, text);
                            } else {
                                System.err.printf("[%s]%s/%s: %s%n", type, level, tag, text);
                            }
                        }
                    } catch (IOException e) {
                        throw new IllegalStateException(e);
                    }
                }
            };
            return 0;
        }

        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }
}
