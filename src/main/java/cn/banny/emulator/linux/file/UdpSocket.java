package cn.banny.emulator.linux.file;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.LinuxEmulator;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.io.IOException;
import java.net.*;

public class UdpSocket extends SocketIO implements FileIO {

    private static final Log log = LogFactory.getLog(UdpSocket.class);

    private final Emulator emulator;
    private final DatagramSocket datagramSocket;

    public UdpSocket(Emulator emulator) {
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
    int connect_ipv6(Pointer addr, int addrlen) {
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
            emulator.getMemory().setErrno(LinuxEmulator.ECONNREFUSED);
            return -1;
        }
    }

    @Override
    int connect_ipv4(Pointer addr, int addrlen) {
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
            emulator.getMemory().setErrno(LinuxEmulator.ECONNREFUSED);
            return -1;
        }
    }

    @Override
    InetSocketAddress getLocalSocketAddress() {
        return (InetSocketAddress) datagramSocket.getLocalSocketAddress();
    }

    @Override
    public int write(byte[] data) {
        throw new AbstractMethodError();
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
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
            emulator.getMemory().setErrno(LinuxEmulator.EACCES);
            return -1;
        }
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
    void setReuseAddress(int reuseAddress) {
        throw new AbstractMethodError();
    }

    @Override
    void setTcpNoDelay(int tcpNoDelay) {
        throw new AbstractMethodError();
    }

    @Override
    int getTcpNoDelay() {
        throw new AbstractMethodError();
    }
}
