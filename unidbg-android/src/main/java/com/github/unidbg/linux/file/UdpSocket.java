package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.linux.struct.IFConf;
import com.github.unidbg.linux.struct.IFReq;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.SockAddr;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.BufferOverflowException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class UdpSocket extends SocketIO implements FileIO {

    private static final Logger log = LoggerFactory.getLogger(UdpSocket.class);

    private final Emulator<?> emulator;
    private final DatagramSocket datagramSocket;

    public UdpSocket(Emulator<?> emulator) {
        this.emulator = emulator;
        try {
            this.datagramSocket = new DatagramSocket();
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
        if (emulator.getSyscallHandler().isVerbose()) {
            System.out.printf("Udp opened '%s' from %s%n", this, emulator.getContext().getLRPointer());
        }
    }

    @Override
    public String toString() {
        return datagramSocket.toString();
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
    protected void setSendBufferSize(int size) {
        throw new AbstractMethodError();
    }

    @Override
    protected void setReceiveBufferSize(int size) {
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
        if (request == SIOCGIFFLAGS) {
            return getIFaceFlags(emulator, argp);
        }
        if (request == SIOCGIFNAME) {
            return getIFaceName(emulator, argp);
        }

        return super.ioctl(emulator, request, argp);
    }

    private int getIFaceList(Emulator<?> emulator, long argp) {
        try {
            List<NetworkIF> list = getNetworkIFs(emulator);
            IFConf conf = IFConf.create(emulator, UnidbgPointer.pointer(emulator, argp));
            Pointer ifcu_req = UnidbgPointer.pointer(emulator, conf.getIfcuReq());
            IFReq ifReq = IFReq.createIFReq(emulator, ifcu_req);
            if (list.size() * ifReq.size() > conf.ifc_len) {
                throw new BufferOverflowException();
            }

            conf.ifc_len = list.size() * ifReq.size();
            conf.pack();

            Pointer pointer = Objects.requireNonNull(ifcu_req);
            for (NetworkIF networkIF : list) {
                ifReq = IFReq.createIFReq(emulator, pointer);
                ifReq.setName(networkIF.ifName);
                ifReq.pack();

                SockAddr sockAddr = new SockAddr(ifReq.getAddrPointer());
                sockAddr.sin_family = AF_INET;
                sockAddr.sin_port = 0;
                sockAddr.sin_addr = Arrays.copyOf(networkIF.ipv4.getAddress(), IPV4_ADDR_LEN - 4);
                sockAddr.pack();

                pointer = pointer.share(ifReq.size());
            }

            return 0;
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
    }

    protected int getIFaceFlags(Emulator<?> emulator, long argp) {
        IFReq req = IFReq.createIFReq(emulator, UnidbgPointer.pointer(emulator, argp));
        req.unpack();
        String ifName = new String(req.ifrn_name).trim();
        if (log.isDebugEnabled()) {
            log.debug("get iface flags: {}", ifName);
        }
        NetworkIF selected = null;
        try {
            for (NetworkIF networkIF : getNetworkIFs(emulator)) {
                if (ifName.equals(networkIF.ifName)) {
                    selected = networkIF;
                    break;
                }
            }
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
        if (selected == null) {
            throw new UnsupportedOperationException("getIFaceFlags: " + ifName);
        }
        Pointer ptr = req.getAddrPointer();
        int flags = IFF_UP | IFF_RUNNING;
        if (selected.isLoopback()) {
            flags |= IFF_LOOPBACK;
        } else if(selected.broadcast != null) {
            flags |= IFF_BROADCAST;
            flags |= IFF_MULTICAST;
        }
        ptr.setShort(0, (short) flags);
        return 0;
    }

    protected int getIFaceName(Emulator<?> emulator, long argp) {
        IFReq req = IFReq.createIFReq(emulator, UnidbgPointer.pointer(emulator, argp));
        Pointer ptr = req.getAddrPointer();
        int ifindex = ptr.getInt(0);
        if (log.isDebugEnabled()) {
            log.debug("get iface name: {}", ifindex);
        }
        try {
            List<NetworkIF> list = getNetworkIFs(emulator);
            for (NetworkIF networkIF : list) {
                if (ifindex == networkIF.index) {
                    req.setName(networkIF.ifName);
                    req.pack();
                    return 0;
                }
            }
            throw new IllegalStateException("ifindex=" + ifindex);
        } catch (SocketException e) {
            throw new IllegalStateException(e);
        }
    }

}
