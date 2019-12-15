package cn.banny.unidbg.linux.file;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.unix.UnixEmulator;
import cn.banny.unidbg.unix.file.SocketIO;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class LocalSocketIO extends SocketIO implements FileIO {

    private static final Log log = LogFactory.getLog(LocalSocketIO.class);

    private interface SocketHandler {
        byte[] handle(byte[] request) throws IOException;
        int fstat(Pointer stat);
    }

    private final Emulator emulator;

    public LocalSocketIO(Emulator emulator) {
        this.emulator = emulator;
    }

    @Override
    public void close() {
        response = null;
        handler = null;
    }

    private byte[] response;

    @Override
    public int write(byte[] data) {
        try {
            byte[] response = handler.handle(data);
            if (response != null) {
                this.response = response;
            }
            return data.length;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        if (response == null) {
            throw new IllegalStateException("response is null");
        }
        if (response.length <= count) {
            buffer.write(0, response, 0, response.length);
            int ret = response.length;
            response = null;
            return ret;
        } else {
            buffer.write(0, Arrays.copyOf(response, count), 0, count);
            byte[] temp = new byte[response.length - count];
            System.arraycopy(response, count, temp, 0, temp.length);
            response = temp;
            return count;
        }
    }

    @Override
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        return handler.fstat(stat);
    }

    @Override
    protected InetSocketAddress getLocalSocketAddress() {
        throw new AbstractMethodError();
    }

    private SocketHandler handler;

    @Override
    public int connect(Pointer addr, int addrlen) {
        short sa_family = addr.getShort(0);
        if (sa_family != AF_LOCAL) {
            throw new UnsupportedOperationException("sa_family=" + sa_family);
        }
        String path = addr.getString(2);
        log.debug("connect sa_family=" + sa_family + ", path=" + path);
        switch (path) {
            case "/dev/socket/dnsproxyd":
                handler = new SocketHandler() {
                    private static final int DnsProxyQueryResult       = 222;
                    private static final int DnsProxyOperationFailed   = 401;
                    private final ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
                    @Override
                    public int fstat(Pointer stat) {
                        stat.setLong(0x30, 0); // st_size
                        stat.setInt(0x38, 0); // st_blksize
                        return 0;
                    }
                    @Override
                    public byte[] handle(byte[] request) throws IOException {
                        baos.write(request);
                        byte[] data = baos.toByteArray();
                        int endIndex = -1;
                        for (int i = 0; i < data.length; i++) {
                            if (data[i] == 0) {
                                endIndex = i;
                                break;
                            }
                        }
                        if (endIndex == -1) {
                            return null;
                        }
                        baos.reset();
                        String command = new String(data, 0, endIndex);
                        if (command.startsWith("getaddrinfo")) {
                            return getaddrinfo(command);
                        } else if (command.startsWith("gethostbyaddr")) {
                            return gethostbyaddr(command);
                        }
                        throw new AbstractMethodError();
                    }
                    private byte[] gethostbyaddr(String command) {
                        ByteBuffer buffer = ByteBuffer.allocate(1024);

                        String[] tokens = command.split("\\s");
                        String addr = tokens[1];

                        try {
                            InetAddress address = InetAddress.getByName(addr);
                            String host = address.getCanonicalHostName();
                            if (host != null && host.equals(addr)) {
                                host = null;
                            }

                            if (host == null) {
                                throw new UnknownHostException();
                            } else {
                                buffer.put((DnsProxyQueryResult + "\0").getBytes());
                                byte[] bytes = host.getBytes(StandardCharsets.UTF_8);
                                buffer.putInt(bytes.length + 1);
                                buffer.put(bytes);
                                buffer.put((byte) 0); // NULL-terminated string

                                buffer.putInt(0); // null to indicate we're done aliases

                                buffer.putInt(SocketIO.AF_INET); // addrtype
                                buffer.putInt(4); // unknown length

                                buffer.putInt(0); // null to indicate we're done addr_list
                            }
                        } catch (UnknownHostException e) {
                            buffer.put((DnsProxyOperationFailed + "\0").getBytes());
                            buffer.putInt(0);
                        }

                        buffer.flip();
                        byte[] response = new byte[buffer.remaining()];
                        buffer.get(response);
                        if (log.isDebugEnabled()) {
                            Inspector.inspect(response, "gethostbyaddr");
                        }
                        return response;
                    }
                    private byte[] getaddrinfo(String command) {
                        String[] tokens = command.split("\\s");
                        String hostname = tokens[1];
                        String servername = tokens[2];
                        short port = 0;
                        if (!"^".equals(servername)) {
                            try { port = Short.parseShort(servername); } catch(NumberFormatException ignored) {}
                        }
                        int ai_flags = Integer.parseInt(tokens[3]);
                        int ai_family = Integer.parseInt(tokens[4]);
                        int ai_socktype = Integer.parseInt(tokens[5]);
                        int ai_protocol = Integer.parseInt(tokens[6]);

                        ByteBuffer buffer = ByteBuffer.allocate(1024);
                        try {
                            InetAddress[] addresses = InetAddress.getAllByName(hostname);
                            log.debug("getaddrinfo hostname=" + hostname + ", servername=" + servername + ", addresses=" + Arrays.toString(addresses) + ", ai_flags=" + ai_flags + ", ai_family=" + ai_family + ", ai_socktype=" + ai_socktype + ", ai_protocol=" + ai_protocol);
                            buffer.put((DnsProxyQueryResult + "\0").getBytes());

                            for (InetAddress address : addresses) {
                                buffer.order(ByteOrder.BIG_ENDIAN);
                                buffer.putInt(32); // sizeof(struct addrinfo)
                                buffer.order(ByteOrder.LITTLE_ENDIAN);
                                buffer.putInt(ai_flags);
                                buffer.putInt(SocketIO.AF_INET);
                                buffer.putInt(ai_socktype);
                                buffer.putInt(SocketIO.IPPROTO_TCP);
                                buffer.putInt(16); // ai_addrlen
                                buffer.putInt(0); // ai_canonname
                                buffer.putInt(0); // ai_addr
                                buffer.putInt(0); // ai_next
                                buffer.order(ByteOrder.BIG_ENDIAN);
                                buffer.putInt(16); // ai_addrlen
                                buffer.order(ByteOrder.LITTLE_ENDIAN);
                                buffer.putShort((short) SocketIO.AF_INET); // sin_family
                                buffer.putShort(Short.reverseBytes(port)); // sin_port
                                buffer.put(Arrays.copyOf(address.getAddress(), 4));
                                buffer.put(new byte[8]); // __pad
                                buffer.order(ByteOrder.BIG_ENDIAN);
                                buffer.putInt(0); // ai_canonname
                            }

                            buffer.order(ByteOrder.BIG_ENDIAN);
                            buffer.putInt(0); // NULL-terminated
                        } catch (UnknownHostException e) {
                            final int EAI_NODATA = 7;
                            buffer.put((DnsProxyOperationFailed + "\0").getBytes());
                            buffer.putInt(4);
                            buffer.order(ByteOrder.LITTLE_ENDIAN).putInt(EAI_NODATA);
                        }

                        buffer.flip();
                        byte[] response = new byte[buffer.remaining()];
                        buffer.get(response);
                        if (log.isDebugEnabled()) {
                            Inspector.inspect(response, "getaddrinfo");
                        }
                        return response;
                    }
                };
                return 0;
        }

        emulator.getMemory().setErrno(UnixEmulator.EPERM);
        return -1;
    }

    @Override
    protected int connect_ipv6(Pointer addr, int addrlen) {
        throw new AbstractMethodError();
    }

    @Override
    protected int connect_ipv4(Pointer addr, int addrlen) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setReuseAddress(int reuseAddress) {
    }

    @Override
    protected void setKeepAlive(int keepAlive) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setSocketRecvBuf(int recvBuf) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setTcpNoDelay(int tcpNoDelay) {
        throw new AbstractMethodError();
    }

    @Override
    protected int getTcpNoDelay() {
        throw new AbstractMethodError();
    }
}
