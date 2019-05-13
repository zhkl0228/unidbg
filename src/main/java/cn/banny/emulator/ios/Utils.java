package cn.banny.emulator.ios;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Utils {

    /**
     * Reads an signed integer from {@code buffer}.
     */
    public static long readSignedLeb128(ByteBuffer buffer) {
        long result = 0;
        int cur;
        int count = 0;
        int signBits = -1;

        do {
            cur = buffer.get() & 0xff;
            result |= (cur & 0x7f) << (count * 7);
            signBits <<= 7;
            count++;
        } while ((cur & 0x80) == 0x80);

        if ((cur & 0x80) == 0x80) {
            throw new IllegalArgumentException("invalid LEB128 sequence");
        }

        // Sign extend if appropriate
        if (((signBits >> 1) & result) != 0) {
            result |= signBits;
        }

        return result;
    }

    /**
     * Reads an unsigned leb128 integer from {@code buffer}.
     */
    public static long readUnsignedLeb128(ByteBuffer buffer) {
        long result = 0;
        int cur;
        int count = 0;

        do {
            cur = buffer.get() & 0xff;
            result |= (cur & 0x7f) << (count * 7);
            count++;
        } while ((cur & 0x80) == 0x80);

        if ((cur & 0x80) == 0x80) {
            throw new IllegalArgumentException("invalid LEB128 sequence");
        }

        return result;
    }

    static BigInteger readULEB128(ByteBuffer buffer) {
        BigInteger result = BigInteger.ZERO;
        int shift = 0;
        while (true) {
            byte b = buffer.get();
            result = result.or(BigInteger.valueOf(b & 127).shiftLeft(shift));
            if ((b & 128) == 0) {
                break;
            }
            shift += 7;
        }
        return result;
    }

}
