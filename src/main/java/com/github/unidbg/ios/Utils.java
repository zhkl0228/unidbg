package com.github.unidbg.ios;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Utils {

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

    static BigInteger readULEB128(ByteBuffer buffer) {
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
