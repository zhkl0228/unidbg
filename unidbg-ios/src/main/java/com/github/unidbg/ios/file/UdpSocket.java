package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.ios.struct.attr.AttrList;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;

public class UdpSocket extends SocketIO implements FileIO {

    private static final Log log = LogFactory.getLog(UdpSocket.class);

    private final Emulator<?> emulator;
    private final DatagramSocket datagramSocket;

    public UdpSocket(Emulator<?> emulator) {
        this.emulator = emulator;
        try {
            this.datagramSocket = new DatagramSocket();
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        this.datagramSocket.close();
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
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(addr.getByteArray(4, 16)), port);
            datagramSocket.connect(address);
            return 0;
        } catch (IOException e) {
            log.debug("connect ipv6 failed", e);
            emulator.getMemory().setErrno(UnixEmulator.ECONNREFUSED);
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
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(addr.getByteArray(8, 4)), port);
            datagramSocket.connect(address);
            return 0;
        } catch (IOException e) {
            log.debug("connect ipv4 failed", e);
            emulator.getMemory().setErrno(UnixEmulator.ECONNREFUSED);
            return -1;
        }
    }

    @Override
    protected InetSocketAddress getLocalSocketAddress() {
        return (InetSocketAddress) datagramSocket.getLocalSocketAddress();
    }

    @Override
    public int write(byte[] data) {
        throw new AbstractMethodError();
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        throw new AbstractMethodError();
    }

    @Override
    public FileIO dup2() {
        return new UdpSocket(emulator);
    }

    @Override
    public int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen) {
        if (addrlen != 16) {
            throw new IllegalStateException("addrlen=" + addrlen);
        }

        if (log.isDebugEnabled()) {
            byte[] addr = dest_addr.getByteArray(0, addrlen);
            Inspector.inspect(addr, "addr");
        }

        int sa_family = dest_addr.getInt(0);
        if (sa_family != AF_INET) {
            throw new AbstractMethodError("sa_family=" + sa_family);
        }

        try {
            InetAddress address = InetAddress.getByAddress(dest_addr.getByteArray(4, 4));
            throw new UnsupportedOperationException("address=" + address);
        } catch (IOException e) {
            log.debug("sendto failed", e);
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
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
    protected void setReuseAddress(int reuseAddress) {
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

    @Override
    public int getattrlist(AttrList attrList, Pointer attrBuf, int attrBufSize) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getdirentries64(Pointer buf, int bufSize) {
        throw new UnsupportedOperationException();
    }
}
