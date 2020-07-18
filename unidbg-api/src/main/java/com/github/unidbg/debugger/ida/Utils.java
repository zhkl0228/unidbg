package com.github.unidbg.debugger.ida;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Utils {

    public static String readCString(ByteBuffer buffer) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int read;
        while ((read = buffer.get() & 0xff) != 0) {
            baos.write(read);
        }
        return baos.toString();
    }

    public static void writeCString(ByteBuffer buffer, String str) {
        byte[] data = str.getBytes(StandardCharsets.UTF_8);
        buffer.put(Arrays.copyOf(data, data.length + 1));
    }

    public static long unpack_dd(ByteBuffer buffer) {
        byte b = buffer.get();
        if ((b & 0xff) == 0xff) {
            return buffer.getInt() & 0xffffffffL;
        } else if ((b & 0xc0) == 0xc0) {
            int b0 = b & 0x3f;
            int b1 = buffer.get() & 0xff;
            int b2 = buffer.get() & 0xff;
            int b3 = buffer.get() & 0xff;
            return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffffL;
        } else if ((b & 0x80) == 0x80) {
            int b0 = b & 0x7f;
            int b1 = buffer.get() & 0xff;
            return (b0 << 8) | b1;
        } else {
            return b & 0xff;
        }
    }

    public static long unpack_dq(ByteBuffer buffer) {
        long low = unpack_dd(buffer);
        long high = unpack_dd(buffer);
        return (high << 32L) | low;
    }

    public static byte[] pack_dq(long value) {
        byte[] d1 = pack_dd(value);
        byte[] d2 = pack_dd(value >> 32);
        byte[] data = new byte[d1.length + d2.length];
        System.arraycopy(d1, 0, data, 0, d1.length);
        System.arraycopy(d2, 0, data, d1.length, d2.length);
        return data;
    }

    public static byte[] pack_dd(long value) {
        value &= 0xffffffffL; // unsigned int

        ByteBuffer buffer = ByteBuffer.allocate(0x10);
        if (value <= 0x7f) {
            buffer.put((byte) value);
            return flipBuffer(buffer);
        }

        if ((value >> 14) == 0) {
            buffer.put((byte) ((value >> 8) | 0x80));
            buffer.put((byte) value);
            return flipBuffer(buffer);
        }

        if ((value >> 29) == 0) {
            buffer.putInt((int) (value | 0xc0000000));
        } else {
            buffer.put((byte) 0xff);
            buffer.putInt((int) value);
        }
        return flipBuffer(buffer);
    }

    public static byte[] flipBuffer(ByteBuffer buffer) {
        buffer.flip();
        byte[] data = new byte[buffer.remaining()];
        buffer.get(data);
        return data;
    }

}
