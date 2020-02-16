package com.github.unidbg;

import junit.framework.TestCase;
import org.apache.commons.io.FileUtils;

import java.io.File;
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

}
