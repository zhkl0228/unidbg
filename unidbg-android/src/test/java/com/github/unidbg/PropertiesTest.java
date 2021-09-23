package com.github.unidbg;

import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PropertiesTest extends TestCase {

    private static final int PROP_AREA_MAGIC = 0x504f5250;
    private static final int PROP_AREA_VERSION = 0xfc6ed0ab;

    public void testParse() throws Exception {
        File file = new File("src/main/resources/android/sdk19/dev/__properties__");
        ByteBuffer buffer = ByteBuffer.allocate((int) file.length());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(FileUtils.readFileToByteArray(file));
        buffer.flip();

        buffer.position(8);
        int magic = buffer.getInt();
        int version = buffer.getInt();
        assertEquals(PROP_AREA_MAGIC, magic);
        assertEquals(PROP_AREA_VERSION, version);
        for (int i = 0; i < 28; i++) {
            buffer.getInt(); // reserved
        }

        int startPos = buffer.position();

        String[] props = new String[]{
                "ro.build.version.sdk",
                "ro.serialno",
                "ro.build.version.release",
                "persist.sys.root_access"
        };
        for (String key : props) {
            System.err.println(key + "=" + findProperty(buffer, startPos, key));
        }
    }

    private static String findProperty(ByteBuffer buffer, int startPos, String name) {
        PropBt current = new PropBt(buffer, startPos);
        while (true) {
            int index = name.indexOf('.');
            boolean want_subtree = index != -1;
            int children_offset = current.children;
            if (children_offset == 0) {
                throw new IllegalStateException("children_offset=" + children_offset);
            }

            PropBt root = new PropBt(buffer, startPos + children_offset);
            current = find_prop_bt(buffer, root, want_subtree ? name.substring(0, index) : name, startPos);
            if (current == null) {
                if (!want_subtree) {
                    return null;
                }
                throw new IllegalStateException("current is null");
            }

            if (want_subtree) {
                name = name.substring(index + 1);
            } else {
                return current.readProp(buffer, startPos + current.prop);
            }
        }
    }

    private static PropBt find_prop_bt(ByteBuffer buffer, PropBt bt, String name, int startPos) {
        PropBt current = bt;
        while (true) {
            String currentName = current.name;
            int ret = cmp_prop_name(name, currentName, current.nameLen);
            System.out.println("find_prop_bt name=" + name + ", currentName=" + currentName + ", ret=" + ret);
            if (ret == 0) {
                return current;
            } else if (ret > 0) {
                int right_offset = current.right;
                if (right_offset != 0) {
                    current = new PropBt(buffer, startPos + right_offset);
                } else {
                    return null;
                }
            } else {
                int left_offset = current.left;
                if (left_offset != 0) {
                    current = new PropBt(buffer, startPos + left_offset);
                } else {
                    return null;
                }
            }
        }
    }

    private static int cmp_prop_name(String name, String currentName, int namelen) {
        if (name.length() < namelen) {
            return -1;
        }
        if (name.length() > namelen) {
            return 1;
        }
        return name.compareTo(currentName);
    }

    private static class PropBt {
        final int nameLen;
        final int prop;
        final int left;
        final int right;
        final int children;
        final String name;
        public PropBt(ByteBuffer buffer, int off) {
            buffer.position(off);
            nameLen = buffer.get() & 0xff;
            buffer.get(new byte[3]);
            prop = buffer.getInt();
            left = buffer.getInt();
            right = buffer.getInt();
            children = buffer.getInt();
            name = readName(buffer);
            System.out.println("new PropBt off=0x" + Integer.toHexString(off) + ", namelen=0x" + Integer.toHexString(nameLen) + ", name=" + name);
        }
        private String readName(ByteBuffer buffer) {
            byte[] data = new byte[nameLen];
            buffer.get(data);
            return new String(data);
        }
        private String readProp(ByteBuffer buffer, int off) {
            buffer.position(off);
            int serial = buffer.getInt();
            int len = serial >> 24;
            byte[] data = new byte[len];
            buffer.get(data);
            return new String(data);
        }
    }

    public void testAlignment() {
        for (int i = 200; i >= 100; i--) {
            int v = i;
            v &= (~15);
            System.out.println("i=" + i + ", v=" + v);
        }
    }

    public void testHex() throws Exception {
        byte[] data = Hex.decodeHex("4c0000001400020000000000f53e0000020880fe01000000080001007f000001080002007f000001070003006c6f0000080008008000000014000600ffffffffffffffff0203000002030000580000001400020000000000f53e0000021880001700000008000100c0a81fa808000200c0a81fa808000400c0a81fff0a000300776c616e30000000080008008000000014000600ffffffffffffffff7433b7007433b700".toCharArray());
        Inspector.inspect(data, "Hex");
        decodeNetlinkMsg(data);

        data = Hex.decodeHex("4c0000001400020000000000a73e0000020880fe01000000080001007f000001080002007f000001070003006c6f0000080008008000000014000600ffffffffffffffff0203000002030000580000001400020000000000a73e0000021880001700000008000100c0a81fa808000200c0a81fa808000400c0a81fff0a000300776c616e30000000080008008000000014000600ffffffffffffffff7433b7007433b700".toCharArray());
        Inspector.inspect(data, "Hex");
        decodeNetlinkMsg(data);
    }

    private void decodeNetlinkMsg(byte[] data) throws UnknownHostException {
        final int SIZE_OF_NLMSGHDR = 16;
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.remaining() >= SIZE_OF_NLMSGHDR) {
            int nlmsg_len = buffer.getInt();
            byte[] tmp = new byte[nlmsg_len - 4];
            buffer.get(tmp);
            ByteBuffer bb = ByteBuffer.wrap(tmp);
            bb.order(ByteOrder.LITTLE_ENDIAN);

            short nlmsg_type = bb.getShort();
            short nlmsg_flags = bb.getShort();
            int nlmsg_seq = bb.getInt();
            int nlmsg_pid = bb.getInt();

            byte ifa_family = bb.get();
            byte ifa_prefixlen = bb.get();  /* The prefix length		*/
            byte ifa_flags = bb.get();      /* Flags			*/
            byte ifa_scope = bb.get();      /* Address scope		*/
            int ifa_index = bb.getInt();    /* Link index			*/

            byte[] remaining = new byte[bb.remaining()];
            bb.get(remaining);
            Inspector.inspect(remaining, "nlmsg_type=0x" + Integer.toHexString(nlmsg_type) + ", nlmsg_flags=0x" + Integer.toHexString(nlmsg_flags) +
                    ", nlmsg_seq=" + nlmsg_seq + ", nlmsg_pid=" + nlmsg_pid +
                    ", ifa_family=" + ifa_family + ", ifa_prefixlen=" + ifa_prefixlen + ", ifa_flags=0x" + Integer.toHexString(ifa_flags & 0xff) + ", ifa_scope=" + ifa_scope +
                    ", ifa_index=" + ifa_index);

            final int IFA_ADDRESS = 1;
            final int IFA_LOCAL = 2;
            final int IFA_LABEL = 3;
            final int IFA_BROADCAST = 4;
            final int IFA_CACHEINFO = 6;
            final int __IFA_MAX = 8;
            bb = ByteBuffer.wrap(remaining);
            bb.order(ByteOrder.LITTLE_ENDIAN);
            while (bb.hasRemaining()) {
                short rta_len = bb.getShort();
                short rta_type = bb.getShort();
                switch (rta_type) {
                    case IFA_ADDRESS:
                    case IFA_LOCAL:
                    case IFA_BROADCAST:
                        if (rta_len != 8) {
                            throw new UnsupportedOperationException("rta_len=" + rta_len);
                        }
                        byte[] addr = new byte[4];
                        bb.get(addr);
                        InetAddress address = Inet4Address.getByAddress(addr);
                        System.out.println("addr" + rta_type + ": " + address);
                        break;
                    case IFA_LABEL:
                        String label = Utils.readCString(bb);
                        System.out.println("label: " + label);
                        break;
                    case IFA_CACHEINFO: // struct ifa_cacheinfo
                        int ifa_prefered = bb.getInt();
                        int ifa_valid = bb.getInt();
                        int cstamp = bb.getInt(); /* created timestamp, hundredths of seconds */
                        int tstamp = bb.getInt(); /* updated timestamp, hundredths of seconds */
                        System.out.println("ifa_prefered=" + ifa_prefered + ", ifa_valid=" + ifa_valid + ", cstamp=" + cstamp + ", tstamp=" + tstamp);
                        break;
                    case __IFA_MAX:
                        if (rta_len != 8) {
                            throw new UnsupportedOperationException("rta_len=" + rta_len);
                        }
                        int ifaMax = bb.getInt();
                        System.out.println("ifaMax: " + ifaMax);
                        break;
                    default:
                        throw new UnsupportedOperationException("rta_type=" + rta_type);
                }
                int align = rta_len % 4;
                for (int i = align; align > 0 && i < 4; i++) {
                    bb.get();
                }
            }
        }
    }

}
