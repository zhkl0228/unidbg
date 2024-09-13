package com.github.unidbg.linux.file;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;

public class TcpSocket extends SocketIO implements FileIO {

    private static final Logger log = LoggerFactory.getLogger(TcpSocket.class);

    private final Socket socket;
    private ServerSocket serverSocket;

    private final Emulator<?> emulator;

    public TcpSocket(Emulator<?> emulator) {
        this(emulator, new Socket());
    }

    private TcpSocket(Emulator<?> emulator, Socket socket) {
        this.emulator = emulator;
        this.socket = socket;
        if (emulator.getSyscallHandler().isVerbose()) {
            System.out.printf("Tcp opened '%s' from %s%n", this, emulator.getContext().getLRPointer());
        }
    }

    protected OutputStream outputStream;
    protected InputStream inputStream;

    @Override
    public void close() {
        IOUtils.close(outputStream);
        IOUtils.close(inputStream);
        IOUtils.close(socket);
        IOUtils.close(serverSocket);
    }

    @Override
    public int write(byte[] data) {
        try {
            if (log.isDebugEnabled()) {
                Inspector.inspect(data, "write hex=" + Hex.encodeHexString(data));
            }
            outputStream.write(data);
            return data.length;
        } catch (IOException e) {
            log.debug("write failed", e);
            return -1;
        }
    }

    @Override
    public int recvfrom(Backend backend, Pointer buf, int len, int flags, Pointer src_addr, Pointer addrlen) {
        boolean peek = (flags & MSG_PEEK) != 0;
        if (peek &&
                (flags & ~MSG_PEEK) == 0 &&
                inputStream.markSupported() &&
                src_addr == null && addrlen == null) {
            try {
                inputStream.mark(len);
                return readInternal(buf, len, false);
            } finally {
                try {
                    inputStream.reset();
                } catch (IOException e) {
                    log.warn("recvfrom", e);
                }
            }
        }

        return super.recvfrom(backend, buf, len, flags, src_addr, addrlen);
    }

    private byte[] receiveBuf;

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        return readInternal(buffer, count, true);
    }

    protected int readInternal(Pointer buffer, int count, boolean logRead) {
        try {
            if (receiveBuf == null) {
                receiveBuf = new byte[socket.getReceiveBufferSize()];
            }
            int read = inputStream.read(receiveBuf, 0, Math.min(count, receiveBuf.length));
            if (read <= 0) {
                return read;
            }

            byte[] data = Arrays.copyOf(receiveBuf, read);
            buffer.write(0, data, 0, data.length);
            if (logRead && log.isDebugEnabled()) {
                Inspector.inspect(data, "readInternal socket=" + socket);
            }
            return data.length;
        } catch (IOException e) {
            log.debug("readInternal", e);
            return -1;
        }
    }

    @Override
    public int listen(int backlog) {
        try {
            serverSocket = new ServerSocket();
            com.alibaba.fastjson.util.IOUtils.close(socket);
            serverSocket.bind(socket.getLocalSocketAddress(), backlog);
            return 0;
        } catch (IOException e) {
            log.debug("listen failed", e);
            emulator.getMemory().setErrno(UnixEmulator.EOPNOTSUPP);
            return -1;
        }
    }

    @Override
    public AndroidFileIO accept(Pointer addr, Pointer addrlen) {
        try {
            Socket socket = serverSocket.accept();
            TcpSocket io = new TcpSocket(emulator, socket);
            io.inputStream = new BufferedInputStream(socket.getInputStream());
            io.outputStream = socket.getOutputStream();
            if (addr != null) {
                io.getpeername(addr, addrlen);
            }
            return io;
        } catch (IOException e) {
            log.debug("accept failed", e);
            emulator.getMemory().setErrno(UnixEmulator.EAGAIN);
            return null;
        }
    }

    @Override
    protected int bind_ipv4(Pointer addr, int addrlen) {
        int sa_family = addr.getShort(0);
        if (sa_family != AF_INET) {
            throw new AbstractMethodError("sa_family=" + sa_family);
        }

        try {
            int port = Short.reverseBytes(addr.getShort(2)) & 0xffff;
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(addr.getByteArray(4, 4)), port);
            if (log.isDebugEnabled()) {
                byte[] data = addr.getByteArray(0, addrlen);
                Inspector.inspect(data, "address=" + address);
            }
            socket.bind(address);
            return 0;
        } catch (IOException e) {
            log.debug("bind ipv4 failed", e);
            emulator.getMemory().setErrno(UnixEmulator.EADDRINUSE);
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
            inputStream = new BufferedInputStream(socket.getInputStream());
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
            inputStream = new BufferedInputStream(socket.getInputStream());
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
        fillAddress(remote, addr, addrlen);
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
    protected void setSendBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);

    }

    @Override
    protected void setReceiveBufferSize(int size) throws SocketException {
        socket.setReceiveBufferSize(size);
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
                com.alibaba.fastjson.util.IOUtils.close(outputStream);
                outputStream = null;
                return 0;
            case SHUT_RDWR:
                com.alibaba.fastjson.util.IOUtils.close(outputStream);
                IOUtils.close(inputStream);
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
