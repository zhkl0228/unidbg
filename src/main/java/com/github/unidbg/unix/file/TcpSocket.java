package com.github.unidbg.unix.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.util.Arrays;

public class TcpSocket extends SocketIO implements FileIO {

    private static final Log log = LogFactory.getLog(TcpSocket.class);

    private final Socket socket = new Socket();

    private final Emulator<?> emulator;

    public TcpSocket(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    private OutputStream outputStream;
    private InputStream inputStream;

    @Override
    public void close() {
        IOUtils.closeQuietly(outputStream);
        IOUtils.closeQuietly(inputStream);
        IOUtils.closeQuietly(socket);
    }

    @Override
    public int write(byte[] data) {
        try {
            outputStream.write(data);
            return data.length;
        } catch (IOException e) {
            log.debug("write failed", e);
            return -1;
        }
    }

    private byte[] receiveBuf;

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        try {
            if (receiveBuf == null) {
                receiveBuf = new byte[socket.getReceiveBufferSize()];
            }
            int read = inputStream.read(receiveBuf, 0, count);
            if (read <= 0) {
                return read;
            }

            byte[] data = Arrays.copyOf(receiveBuf, read);
            buffer.write(0, data, 0, data.length);
            if (log.isDebugEnabled()) {
                Inspector.inspect(data, "read");
            }
            return data.length;
        } catch (IOException e) {
            log.debug("read failed", e);
            return -1;
        }
    }

    @Override
    protected int connect_ipv4(Pointer addr, int addrlen) {
        if (log.isDebugEnabled()) {
            byte[] data = addr.getByteArray(0, addrlen);
            Inspector.inspect(data, "addr");
        }

        int sa_family = addr.getShort(0);
        if (sa_family != AF_INET) {
            throw new AbstractMethodError("sa_family=" + sa_family);
        }

        try {
            int port = Short.reverseBytes(addr.getShort(2)) & 0xffff;
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(addr.getByteArray(4, 4)), port);
            socket.connect(address);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            return 0;
        } catch (IOException e) {
            log.debug("connect ipv4 failed", e);
            emulator.getMemory().setErrno(UnixEmulator.ECONNREFUSED);
            return -1;
        }
    }

    @Override
    protected int connect_ipv6(Pointer addr, int addrlen) {
        if (log.isDebugEnabled()) {
            byte[] data = addr.getByteArray(0, addrlen);
            Inspector.inspect(data, "addr");
        }

        int sa_family = addr.getShort(0);
        if (sa_family != AF_INET6) {
            throw new AbstractMethodError("sa_family=" + sa_family);
        }

        try {
            int port = Short.reverseBytes(addr.getShort(2)) & 0xffff;
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(addr.getByteArray(8, 16)), port);
            socket.connect(address);
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            return 0;
        } catch (IOException e) {
            log.debug("connect ipv6 failed", e);
            emulator.getMemory().setErrno(UnixEmulator.ECONNREFUSED);
            return -1;
        }
    }

    @Override
    public int getpeername(Pointer addr, Pointer addrlen) {
        InetSocketAddress remote = (InetSocketAddress) socket.getRemoteSocketAddress();
        addr.setShort(0, (short) AF_INET);
        addr.setShort(2, Short.reverseBytes((short) remote.getPort()));
        addr.write(4, remote.getAddress().getAddress(), 0, 4); // ipv4
        addr.setLong(8, 0);
        addrlen.setInt(0, 16);
        return 0;
    }

    @Override
    protected InetSocketAddress getLocalSocketAddress() {
        return (InetSocketAddress) socket.getLocalSocketAddress();
    }

    @Override
    protected void setKeepAlive(int keepAlive) throws SocketException {
        socket.setKeepAlive(keepAlive != 0);
    }

    @Override
    protected void setSocketRecvBuf(int recvBuf) throws SocketException {
        socket.setReceiveBufferSize(recvBuf);
    }

    @Override
    protected void setReuseAddress(int reuseAddress) throws SocketException {
        socket.setReuseAddress(reuseAddress != 0);
    }

    @Override
    protected void setTcpNoDelay(int tcpNoDelay) throws SocketException {
        socket.setTcpNoDelay(tcpNoDelay != 0);
    }

    @Override
    protected int getTcpNoDelay() throws SocketException {
        return socket.getTcpNoDelay() ? 1 : 0;
    }

    @Override
    public int shutdown(int how) {
        switch (how) {
            case SHUT_RD:
            case SHUT_WR:
                IOUtils.closeQuietly(outputStream);
                outputStream = null;
                return 0;
            case SHUT_RDWR:
                IOUtils.closeQuietly(outputStream);
                IOUtils.closeQuietly(inputStream);
                outputStream = null;
                inputStream = null;
                return 0;
        }

        return super.shutdown(how);
    }

    @Override
    public String toString() {
        return socket.toString();
    }

}
