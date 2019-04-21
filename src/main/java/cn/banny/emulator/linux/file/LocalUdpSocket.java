package cn.banny.emulator.linux.file;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.linux.LinuxEmulator;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class LocalUdpSocket extends SocketIO implements FileIO {

    private static final Log log = LogFactory.getLog(LocalUdpSocket.class);

    private interface UdpHandler {
        void handle(byte[] request) throws IOException;
    }

    private final Emulator emulator;

    public LocalUdpSocket(Emulator emulator) {
        this.emulator = emulator;
    }

    private UdpHandler handler;

    @Override
    public void close() {
        handler = null;
    }

    @Override
    public int write(byte[] data) {
        try {
            handler.handle(data);
            return data.length;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int connect(Pointer addr, int addrlen) {
        short sa_family = addr.getShort(0);
        if (sa_family != AF_LOCAL) {
            throw new UnsupportedOperationException("sa_family=" + sa_family);
        }

        String path = addr.getString(2);
        log.debug("connect sa_family=" + sa_family + ", path=" + path);

        switch (path) {
            case "/dev/socket/logdw":
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
                            log.debug("handle id=" + id + ", tid=" + tid + ", tv_sec=" + tv_sec + ", tv_nsec=" + tv_nsec);

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

                                int level = body[11] & 0xff;
                                String tag = new String(body, 12, tagIndex - 12);
                                String text = new String(body, tagIndex + 1, bodyIndex - tagIndex - 1);
                                final String c;
                                switch (level) {
                                    case LogCatFileIO.VERBOSE:
                                        c = "V";
                                        break;
                                    case LogCatFileIO.DEBUG:
                                        c = "D";
                                        break;
                                    case LogCatFileIO.INFO:
                                        c = "I";
                                        break;
                                    case LogCatFileIO.WARN:
                                        c = "W";
                                        break;
                                    case LogCatFileIO.ERROR:
                                        c = "E";
                                        break;
                                    case LogCatFileIO.ASSERT:
                                        c = "A";
                                        break;
                                    default:
                                        c = level + "";
                                        break;
                                }
                                System.err.println(String.format("[%s]%s/%s: %s", type, c, tag, text));
                            }
                        } catch (IOException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                };
                return 0;
        }

        emulator.getMemory().setErrno(LinuxEmulator.EPERM);
        return -1;
    }

    @Override
    int getTcpNoDelay() {
        throw new AbstractMethodError();
    }

    @Override
    void setTcpNoDelay(int tcpNoDelay) {
        throw new AbstractMethodError();
    }

    @Override
    void setReuseAddress(int reuseAddress) {
        throw new AbstractMethodError();
    }

    @Override
    void setKeepAlive(int keepAlive) {
        throw new AbstractMethodError();
    }

    @Override
    void setSocketRecvBuf(int recvBuf) {
        throw new AbstractMethodError();
    }

    @Override
    InetSocketAddress getLocalSocketAddress() {
        throw new AbstractMethodError();
    }

    @Override
    int connect_ipv6(Pointer addr, int addrlen) {
        throw new AbstractMethodError();
    }

    @Override
    int connect_ipv4(Pointer addr, int addrlen) {
        throw new AbstractMethodError();
    }

}
