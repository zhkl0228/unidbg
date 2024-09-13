package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;

public abstract class LocalUdpSocket extends SocketIO implements FileIO {

    private static final Logger log = LoggerFactory.getLogger(LocalUdpSocket.class);

    protected interface UdpHandler {
        void handle(byte[] request) throws IOException;
    }

    protected final Emulator<?> emulator;

    protected LocalUdpSocket(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    protected UdpHandler handler;

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

    protected abstract int connect(String path);

    @Override
    public int connect(Pointer addr, int addrlen) {
        short sa_family = addr.getShort(0);
        if (sa_family != AF_LOCAL) {
            throw new UnsupportedOperationException("sa_family=" + sa_family);
        }

        String path = addr.getString(2);
        log.debug("connect sa_family={}, path={}", sa_family, path);

        return connect(path);
    }

    @Override
    protected int getTcpNoDelay() {
        throw new AbstractMethodError();
    }

    @Override
    protected void setTcpNoDelay(int tcpNoDelay) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setReuseAddress(int reuseAddress) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setKeepAlive(int keepAlive) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setSendBufferSize(int size) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setReceiveBufferSize(int size) {
        throw new AbstractMethodError();
    }

    @Override
    protected InetSocketAddress getLocalSocketAddress() {
        throw new AbstractMethodError();
    }

    @Override
    protected int connect_ipv6(Pointer addr, int addrlen) {
        throw new AbstractMethodError();
    }

    @Override
    protected int connect_ipv4(Pointer addr, int addrlen) {
        throw new AbstractMethodError();
    }

}
