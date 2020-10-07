package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.unix.UnixEmulator;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class LocalSocketIO extends SocketIO implements FileIO {

    private static final Log log = LogFactory.getLog(LocalSocketIO.class);

    public interface SocketHandler {
        byte[] handle(byte[] request) throws IOException;
        int fstat(StatStructure stat);
    }

    private final Emulator<?> emulator;
    private final int sdk;

    public LocalSocketIO(Emulator<?> emulator, int sdk) {
        this.emulator = emulator;
        this.sdk = sdk;
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
    public int read(Backend backend, Pointer buffer, int count) {
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
    public int fstat(Emulator<?> emulator, StatStructure stat) {
        return handler.fstat(stat);
    }

    @Override
    protected InetSocketAddress getLocalSocketAddress() {
        throw new AbstractMethodError();
    }

    private SocketHandler handler;

    protected SocketHandler resolveHandler(String path) {
        if ("/dev/socket/dnsproxyd".equals(path)) {
            return new DnsProxyDaemon(sdk);
        }
        return null;
    }

    @Override
    public final int connect(final Pointer addr, int addrlen) {
        short sa_family = addr.getShort(0);
        if (sa_family != AF_LOCAL) {
            throw new UnsupportedOperationException("sa_family=" + sa_family);
        }
        String path = new String(addr.getByteArray(2, addrlen - 2), StandardCharsets.UTF_8).trim();
        if (log.isDebugEnabled()) {
            log.debug("connect sa_family=" + sa_family + ", path=" + path);
        }

        handler = resolveHandler(path);
        if (handler != null) {
            return 0;
        } else {
            emulator.getMemory().setErrno(UnixEmulator.EPERM);
            return -1;
        }
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
