package com.github.unidbg.linux.file;

import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class DnsProxyDaemon implements LocalSocketIO.SocketHandler {

    private static final Log log = LogFactory.getLog(DnsProxyDaemon.class);

    private static final int DnsProxyQueryResult = 222;
    private static final int DnsProxyOperationFailed = 401;
    private final ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);

    private final int sdk;

    DnsProxyDaemon(int sdk) {
        this.sdk = sdk;
    }

    @Override
    public int fstat(StatStructure stat) {
        stat.st_size = 0;
        stat.st_blksize = 0;
        stat.pack();
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
        throw new AbstractMethodError(command);
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
            try {
                port = Short.parseShort(servername);
            } catch (NumberFormatException ignored) {
            }
        }
        int ai_flags = Integer.parseInt(tokens[3]);
        int ai_family = Integer.parseInt(tokens[4]);
        int ai_socktype = Integer.parseInt(tokens[5]);
        int ai_protocol = Integer.parseInt(tokens[6]);

        ByteBuffer buffer = ByteBuffer.allocate(1024);
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostname);
            if (log.isDebugEnabled()) {
                log.debug("getaddrinfo hostname=" + hostname + ", servername=" + servername + ", addresses=" + Arrays.toString(addresses) + ", ai_flags=" + ai_flags + ", ai_family=" + ai_family + ", ai_socktype=" + ai_socktype + ", ai_protocol=" + ai_protocol);
            }
            buffer.put((DnsProxyQueryResult + "\0").getBytes());

            for (InetAddress address : addresses) {
                putAddress(buffer, address, ai_flags, ai_socktype, port);
            }

            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.putInt(0); // NULL-terminated
        } catch (UnknownHostException e) {
            final int EAI_NODATA = 7;
            buffer.put((DnsProxyOperationFailed + "\0").getBytes());
            buffer.putInt(4);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(EAI_NODATA);
        }

        buffer.flip();
        byte[] response = new byte[buffer.remaining()];
        buffer.get(response);
        if (log.isDebugEnabled()) {
            Inspector.inspect(response, "getaddrinfo");
        }
        return response;
    }

    private void putAddress(ByteBuffer buffer, InetAddress address, int ai_flags, int ai_socktype, short port) {
        if (sdk == 19) {
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
        } else if (sdk == 23) {
            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.putInt(1); // sizeof(struct addrinfo)
            buffer.putInt(ai_flags);
            buffer.putInt(SocketIO.AF_INET);
            buffer.putInt(ai_socktype);
            buffer.putInt(SocketIO.IPPROTO_TCP);
            buffer.putInt(16); // ai_addrlen
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putShort((short) SocketIO.AF_INET); // sin_family
            buffer.putShort(Short.reverseBytes(port)); // sin_port
            buffer.put(Arrays.copyOf(address.getAddress(), 4));
            buffer.put(new byte[8]); // __pad
            buffer.order(ByteOrder.BIG_ENDIAN);
            buffer.putInt(0); // ai_canonname
        } else {
            throw new IllegalStateException("sdk=" + sdk);
        }
    }
}
