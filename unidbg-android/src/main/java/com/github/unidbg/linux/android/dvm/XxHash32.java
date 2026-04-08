package com.github.unidbg.linux.android.dvm;

import java.nio.charset.StandardCharsets;

/**
 * xxHash32 — pure Java 1.8 implementation.
 * Ported from the original C spec by Yann Collet.
 * <a href="https://github.com/Cyan4973/xxHash">xxHash</a>
 * <br />
 * Thread-safe: all methods are static, no mutable state.
 */
@SuppressWarnings("unused")
public final class XxHash32 implements HashFunction {

    public static final XxHash32 INSTANCE = new XxHash32();

    private static final int PRIME1 = 0x9E3779B1;
    private static final int PRIME2 = 0x85EBCA77;
    private static final int PRIME3 = 0xC2B2AE3D;
    private static final int PRIME4 = 0x27D4EB2F;
    private static final int PRIME5 = 0x165667B1;

    private XxHash32() {}

    // ----------------------------------------------------------------
    // Public API
    // ----------------------------------------------------------------

    /** Hash a String (UTF-8 encoded). */
    @Override
    public int hash(String input) {
        return hash(input, 0);
    }

    /** Hash a String with a custom seed (同 seed 才可跨进程比较). */
    public static int hash(String input, int seed) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        return hash(bytes, 0, bytes.length, seed);
    }

    /** Hash a raw byte array. */
    public static int hash(byte[] data, int offset, int len, int seed) {
        int h32;
        int i = offset;
        final int end = offset + len;

        if (len >= 16) {
            // 4-lane accumulator init
            int v1 = seed + PRIME1 + PRIME2;
            int v2 = seed + PRIME2;
            int v3 = seed;
            int v4 = seed - PRIME1;

            final int limit = end - 16;
            do {
                v1 = round(v1, getInt(data, i));     i += 4;
                v2 = round(v2, getInt(data, i));     i += 4;
                v3 = round(v3, getInt(data, i));     i += 4;
                v4 = round(v4, getInt(data, i));     i += 4;
            } while (i <= limit);

            h32 = Integer.rotateLeft(v1,  1)
                    + Integer.rotateLeft(v2,  7)
                    + Integer.rotateLeft(v3, 12)
                    + Integer.rotateLeft(v4, 18);
        } else {
            h32 = seed + PRIME5;
        }

        h32 += len;

        // consume remaining bytes in 4-byte chunks
        while (i + 4 <= end) {
            h32 += getInt(data, i) * PRIME3;
            h32  = Integer.rotateLeft(h32, 17) * PRIME4;
            i   += 4;
        }

        // consume leftover bytes one at a time
        while (i < end) {
            h32 += (data[i] & 0xFF) * PRIME5;
            h32  = Integer.rotateLeft(h32, 11) * PRIME1;
            i++;
        }

        return fmix(h32);
    }

    // ----------------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------------

    private static int round(int acc, int input) {
        acc += input * PRIME2;
        acc  = Integer.rotateLeft(acc, 13);
        acc *= PRIME1;
        return acc;
    }

    /** Final avalanche mix — ensures every input bit affects every output bit. */
    private static int fmix(int h) {
        h ^= h >>> 15;
        h *= PRIME2;
        h ^= h >>> 13;
        h *= PRIME3;
        h ^= h >>> 16;
        return h;
    }

    /** Read 4 bytes as little-endian int (xxHash spec). */
    private static int getInt(byte[] data, int i) {
        return  (data[i]     & 0xFF)
                | ((data[i + 1] & 0xFF) <<  8)
                | ((data[i + 2] & 0xFF) << 16)
                | ((data[i + 3] & 0xFF) << 24);
    }
}
