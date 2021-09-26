package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileIO;
import com.sun.jna.Pointer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class NetLinkSocket extends SocketIO implements FileIO {

    private static final short RTM_NEWADDR = 0x14;
    private static final short RTM_GETADDR = 0x16;

    private final Emulator<?> emulator;

    public NetLinkSocket(Emulator<?> emulator) {
        this.emulator = emulator;
    }

    private short netlinkType;
    private short netlinkFlags;
    private int netlinkSeq;

    @Override
    public int write(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int size = buffer.getInt();
        if (size - 4 > buffer.remaining()) {
            throw new IllegalStateException("remaining=" + buffer.remaining() + ", size=" + size);
        }
        byte[] tmp = new byte[size - 4];
        buffer.get(tmp);
        buffer = ByteBuffer.wrap(tmp);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        this.netlinkType = buffer.getShort();
        this.netlinkFlags = buffer.getShort();
        this.netlinkSeq = buffer.getInt();
        return size;
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        if (netlinkType == -1) {
            return -1;
        }

        return handleType(buffer, count, netlinkType);
    }

    private static final short NLM_F_REQUEST = 0x1;
    private static final short NLM_F_MULTI = 0x2;
    private static final short NLM_F_MATCH = 0x200;

    protected int handleType(Pointer buffer, int count, short netlinkType) {
        if (netlinkType == RTM_GETADDR && netlinkFlags == (NLM_F_REQUEST | NLM_F_MATCH)) {
            try {
                List<NetworkIF> list = getNetworkIFs(emulator);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ByteBuffer bb = ByteBuffer.allocate(1024);
                bb.order(ByteOrder.LITTLE_ENDIAN);
                for (NetworkIF networkIF : list) {
                    bb.putInt(0); // length placeholder
                    bb.putShort(RTM_NEWADDR);
                    bb.putShort(NLM_F_MULTI);
                    bb.putInt(netlinkSeq);
                    bb.putInt(emulator.getPid());

                    bb.put((byte) AF_INET); // ifa_family
                    bb.put((byte) 0x8); // ifa_prefixlen
                    bb.put((byte) IFF_NOARP); // ifa_flags
                    bb.put((byte) -2); // ifa_scope
                    bb.putInt(networkIF.index);

                    final short IFA_ADDRESS = 1;
                    bb.putShort((short) 0x8); // rta_len
                    bb.putShort(IFA_ADDRESS);
                    bb.put(networkIF.ipv4.getAddress());

                    final short IFA_LOCAL = 2;
                    bb.putShort((short) 0x8); // rta_len
                    bb.putShort(IFA_LOCAL);
                    bb.put(networkIF.ipv4.getAddress());

                    if (networkIF.broadcast != null) {
                        final short IFA_BROADCAST = 4;
                        bb.putShort((short) 0x8); // rta_len
                        bb.putShort(IFA_BROADCAST);
                        bb.put(networkIF.broadcast.getAddress());
                    }

                    final short IFA_LABEL = 3;
                    byte[] label = networkIF.ifName.getBytes(StandardCharsets.UTF_8);
                    int label_len = label.length + 5;
                    bb.putShort((short) label_len); // rta_len
                    bb.putShort(IFA_LABEL);
                    bb.put(Arrays.copyOf(label, label.length + 1));
                    int align = label_len % 4;
                    for (int m = align; align > 0 && m < 4; m++) {
                        bb.put((byte) 0x0);
                    }

                    final short __IFA_MAX = 8;
                    bb.putShort((short) 0x8); // rta_len
                    bb.putShort(__IFA_MAX);
                    bb.putInt(0x80);

                    final short IFA_CACHEINFO = 6;
                    bb.putShort((short) 0x14); // rta_len
                    bb.putShort(IFA_CACHEINFO);
                    bb.putInt(-1); // ifa_prefered
                    bb.putInt(-1); // ifa_valid
                    bb.putInt(100); // cstamp
                    bb.putInt(200); // tstamp
                    bb.flip();

                    int nlmsg_len = bb.remaining();
                    bb.putInt(nlmsg_len);
                    baos.write(bb.array(), 0, nlmsg_len);
                    bb.clear();
                }
                byte[] response = baos.toByteArray();
                if (count >= response.length) {
                    buffer.write(0, response, 0, response.length);
                    this.netlinkType = -1;
                    return response.length;
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        throw new UnsupportedOperationException("buffer=" + buffer + ", count=" + count + ", netlinkType=0x" + Integer.toHexString(netlinkType));
    }

    @Override
    protected int getTcpNoDelay() {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected void setTcpNoDelay(int tcpNoDelay) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected void setReuseAddress(int reuseAddress) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected void setKeepAlive(int keepAlive) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected void setSendBufferSize(int size) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected void setReceiveBufferSize(int size) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected InetSocketAddress getLocalSocketAddress() {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected int connect_ipv6(Pointer addr, int addrlen) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    protected int connect_ipv4(Pointer addr, int addrlen) {
        throw new UnsupportedOperationException(getClass().getName());
    }

    @Override
    public void close() {
        netlinkType = 0;
        netlinkFlags = 0;
    }

}
