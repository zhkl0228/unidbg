package com.github.unidbg.unix.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.linux.struct.IFConf;
import com.github.unidbg.linux.struct.IFReq;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.SockAddr;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.io.IOException;
import java.net.*;
import java.nio.BufferOverflowException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

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
    public int ioctl(Emulator<?> emulator, long request, long argp) {
        if (request == SIOCGIFCONF) {
            return getIFaceList(emulator, argp);
        }

        return super.ioctl(emulator, request, argp);
    }

    private static class NetworkIF {
        private final NetworkInterface networkInterface;
        private final Inet4Address inetAddress;
        public NetworkIF(NetworkInterface networkInterface, Inet4Address inetAddress) {
            this.networkInterface = networkInterface;
            this.inetAddress = inetAddress;
        }
    }

    private int getIFaceList(Emulator<?> emulator, long argp) {
        try {
            Enumeration<NetworkInterface> enumeration = NetworkInterface.getNetworkInterfaces();
            List<NetworkIF> list = new ArrayList<>();
            while (enumeration.hasMoreElements()) {
                NetworkInterface networkInterface = enumeration.nextElement();
                Enumeration<InetAddress> inetAddressEnumeration = networkInterface.getInetAddresses();
                while (inetAddressEnumeration.hasMoreElements()) {
                    InetAddress address = inetAddressEnumeration.nextElement();
                    if (address instanceof Inet4Address) {
                        list.add(new NetworkIF(networkInterface, (Inet4Address) address));
                        break;
                    }
                }
            }
            IFConf conf = new IFConf(UnicornPointer.pointer(emulator, argp));
            IFReq ifReq = IFReq.createIFReq(emulator, conf.ifcu_req);
            if (list.size() * ifReq.size() > conf.ifc_len) {
                throw new BufferOverflowException();
            }

            conf.ifc_len = list.size() * ifReq.size();
            conf.pack();

            Pointer pointer = conf.ifcu_req;
            for (NetworkIF networkIF : list) {
                ifReq = IFReq.createIFReq(emulator, pointer);
                ifReq.setName(networkIF.networkInterface.getName());
                ifReq.pack();

                SockAddr sockAddr = new SockAddr(ifReq.getAddrPointer());
                sockAddr.sin_family = AF_INET;
                sockAddr.sin_port = 0;
                sockAddr.sin_addr = Arrays.copyOf(networkIF.inetAddress.getAddress(), IPV4_ADDR_LEN - 4);
                sockAddr.pack();

                pointer = pointer.share(ifReq.size());
            }

            return 0;
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
    }
}
