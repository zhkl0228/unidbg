package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.BaseAndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.struct.SockAddr;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;

public abstract class SocketIO extends BaseAndroidFileIO implements AndroidFileIO {

    private static final Log log = LogFactory.getLog(SocketIO.class);

    public static final short AF_UNSPEC = 0;
    public static final short AF_LOCAL = 1; // AF_UNIX
    public static final short AF_INET = 2;
    public static final short AF_INET6 = 10;
    public static final short AF_ROUTE = 17;		/* Internal Routing Protocol */
    public static final short AF_LINK =		18;		/* Link layer interface */

    protected static final int IPV4_ADDR_LEN = 16;
    protected static final int IPV6_ADDR_LEN = 28;

    public static final int SOCK_STREAM = 1;
    public static final int SOCK_DGRAM = 2;
    public static final int SOCK_RAW = 3;

    private static final int IPPROTO_IP = 0;
    public static final int IPPROTO_ICMP = 1;
    public static final int IPPROTO_TCP = 6;

    protected static final int SOL_SOCKET = 1;

    private static final int SO_REUSEADDR = 2;
    private static final int SO_ERROR = 4;
    private static final int SO_BROADCAST = 6;
    private static final int SO_RCVBUF = 8;
    private static final int SO_KEEPALIVE = 9;
    private static final int SO_RCVTIMEO = 20;
    private static final int SO_SNDTIMEO = 21;
    protected static final int SO_PEERSEC = 31;

    static final int SHUT_RD = 0;
    static final int SHUT_WR = 1;
    static final int SHUT_RDWR = 2;

    private static final int TCP_NODELAY = 1;
    private static final int TCP_MAXSEG = 2;

    protected SocketIO() {
        super(IOConstants.O_RDWR);
    }

    @Override
    public int getsockopt(int level, int optname, Pointer optval, Pointer optlen) {
        try {
            switch (level) {
                case SOL_SOCKET:
                    if (optname == SO_ERROR) {
                        optlen.setInt(0, 4);
                        optval.setInt(0, 0);
                        return 0;
                    }
                    break;
                case IPPROTO_TCP:
                    if (optname == TCP_NODELAY) {
                        optlen.setInt(0, 4);
                        optval.setInt(0, getTcpNoDelay());
                        return 0;
                    }
                    break;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return super.getsockopt(level, optname, optval, optlen);
    }

    protected abstract int getTcpNoDelay() throws SocketException;

    @Override
    public int setsockopt(int level, int optname, Pointer optval, int optlen) {
        try {
            switch (level) {
                case SOL_SOCKET:
                    switch (optname) {
                        case SO_REUSEADDR:
                            if (optlen != 4) {
                                throw new IllegalStateException("optlen=" + optlen);
                            }
                            setReuseAddress(optval.getInt(0));
                            return 0;
                        case SO_BROADCAST:
                            if (optlen != 4) {
                                throw new IllegalStateException("optlen=" + optlen);
                            }
                            optval.getInt(0); // broadcast_pings
                            return 0;
                        case SO_RCVBUF:
                            if (optlen != 4) {
                                throw new IllegalStateException("optlen=" + optlen);
                            }
                            setSocketRecvBuf(optval.getInt(0));
                            return 0;
                        case SO_KEEPALIVE:
                            if (optlen != 4) {
                                throw new IllegalStateException("optlen=" + optlen);
                            }
                            setKeepAlive(optval.getInt(0));
                            return 0;
                        case SO_RCVTIMEO:
                        case SO_SNDTIMEO: {
                            return 0;
                        }
                    }
                    break;
                case IPPROTO_TCP:
                    switch (optname) {
                        case TCP_NODELAY:
                            if (optlen != 4) {
                                throw new IllegalStateException("optlen=" + optlen);
                            }
                            setTcpNoDelay(optval.getInt(0));
                            return 0;
                        case TCP_MAXSEG:
                            if (optlen != 4) {
                                throw new IllegalStateException("optlen=" + optlen);
                            }
                            log.debug("setsockopt TCP_MAXSEG=" + optval.getInt(0));
                            return 0;
                    }
                    break;
                case IPPROTO_IP:
                    return 0;
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        log.warn("setsockopt level=" + level + ", optname=" + optname + ", optval=" + optval + ", optlen=" + optlen);
        return 0;
    }

    protected abstract void setTcpNoDelay(int tcpNoDelay) throws SocketException;

    protected abstract void setReuseAddress(int reuseAddress) throws SocketException;

    protected abstract void setKeepAlive(int keepAlive) throws SocketException;

    protected abstract void setSocketRecvBuf(int recvBuf) throws SocketException;

    @Override
    public int getsockname(Pointer addr, Pointer addrlen) {
        InetSocketAddress local = getLocalSocketAddress();
        fillAddress(local, addr, addrlen);
        return 0;
    }

    protected final void fillAddress(InetSocketAddress socketAddress, Pointer addr, Pointer addrlen) {
        InetAddress address = socketAddress.getAddress();
        SockAddr sockAddr = new SockAddr(addr);
        sockAddr.sin_port = (short) socketAddress.getPort();
        if (address instanceof Inet4Address) {
            sockAddr.sin_family = AF_INET;
            sockAddr.sin_addr = Arrays.copyOf(address.getAddress(), IPV4_ADDR_LEN - 4);
            addrlen.setInt(0, IPV4_ADDR_LEN);
        } else if (address instanceof Inet6Address) {
            sockAddr.sin_family = AF_INET6;
            sockAddr.sin_addr = Arrays.copyOf(address.getAddress(), IPV6_ADDR_LEN - 4);
            addrlen.setInt(0, IPV6_ADDR_LEN);
        } else {
            throw new UnsupportedOperationException();
        }
    }

    protected abstract InetSocketAddress getLocalSocketAddress();

    @Override
    public int connect(Pointer addr, int addrlen) {
        if (addrlen == IPV4_ADDR_LEN) {
            return connect_ipv4(addr, addrlen);
        } else if(addrlen == IPV6_ADDR_LEN) {
            return connect_ipv6(addr, addrlen);
        } else {
            throw new IllegalStateException("addrlen=" + addrlen);
        }
    }

    @Override
    public final int bind(Pointer addr, int addrlen) {
        if (addrlen == IPV4_ADDR_LEN) {
            return bind_ipv4(addr, addrlen);
        } else if(addrlen == IPV6_ADDR_LEN) {
            return bind_ipv6(addr, addrlen);
        } else {
            throw new IllegalStateException("addrlen=" + addrlen);
        }
    }

    protected abstract int connect_ipv6(Pointer addr, int addrlen);

    protected abstract int connect_ipv4(Pointer addr, int addrlen);

    protected int bind_ipv6(Pointer addr, int addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    protected int bind_ipv4(Pointer addr, int addrlen) {
        throw new AbstractMethodError(getClass().getName());
    }

    @Override
    public int recvfrom(Backend backend, Pointer buf, int len, int flags, Pointer src_addr, Pointer addrlen) {
        if (flags == 0x0 && src_addr == null && addrlen == null) {
            return read(backend, buf, len);
        }

        return super.recvfrom(backend, buf, len, flags, src_addr, addrlen);
    }

    @Override
    public int sendto(byte[] data, int flags, Pointer dest_addr, int addrlen) {
        if (flags == 0x0 && dest_addr == null && addrlen == 0) {
            return write(data);
        }

        return super.sendto(data, flags, dest_addr, addrlen);
    }

    @Override
    public int fstat(Emulator<?> emulator, com.github.unidbg.file.linux.StatStructure stat) {
        stat.st_dev = 0;
        stat.st_mode = IO.S_IFSOCK;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_size = 0;
        stat.st_blksize = 0;
        stat.st_ino = 0;
        stat.pack();
        return 0;
    }

    @Override
    public int getdents64(Pointer dirp, int size) {
        throw new UnsupportedOperationException();
    }
}
