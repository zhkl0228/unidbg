package com.github.unidbg;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Utils {

    /** Returns val represented by the specified number of hex digits. */
    private static String digits(long val, int digits) {
        long hi = 1L << (digits * 4);
        return Long.toHexString(hi | (val & (hi - 1))).substring(1);
    }

    public static String toUUID(byte[] data) {
        if (data == null) {
            return null;
        }

        long msb = 0;
        long lsb = 0;
        assert data.length == 16 : "data must be 16 bytes in length";
        for (int i=0; i<8; i++)
            msb = (msb << 8) | (data[i] & 0xff);
        for (int i=8; i<16; i++)
            lsb = (lsb << 8) | (data[i] & 0xff);
        long mostSigBits = msb;
        long leastSigBits = lsb;

        return (digits(mostSigBits >> 32, 8) + "-" +
                digits(mostSigBits >> 16, 4) + "-" +
                digits(mostSigBits, 4) + "-" +
                digits(leastSigBits >> 48, 4) + "-" +
                digits(leastSigBits, 12)).toUpperCase();
    }

    /**
     * Reads an signed integer from {@code buffer}.
     */
    public static long readSignedLeb128(ByteBuffer buffer, int size) {
        int shift = 0;
        long value = 0;
        long b;
        do {
            b = buffer.get() & 0xff;
            value |= ((b & 0x7f) << shift);
            shift += 7;
        } while((b & 0x80) != 0);

        if (shift < size && ((b & 0x40) != 0)) {
            value |= -(1 << shift);
        }

        return value;
    }

    public static BigInteger readULEB128(ByteBuffer buffer) {
        BigInteger result = BigInteger.ZERO;
        int shift = 0;
        while (true) {
            byte b = buffer.get();
            result = result.or(BigInteger.valueOf(b & 0x7f).shiftLeft(shift));
            if ((b & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        return result;
    }

}
