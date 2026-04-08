package com.github.unidbg.linux.android.dvm;

import java.nio.charset.StandardCharsets;

/**
 * @see XxHash32
 */
public interface HashFunction {

    /**
     * FNV-1a
     */
    @SuppressWarnings("unused")
    HashFunction FNV_1A = className -> {
        int h = 0x811c9dc5;  // FNV offset basis
        for (int i = 0; i < className.length(); i++) {
            h ^= className.charAt(i);
            h *= 0x01000193;  // FNV prime
        }
        return h;
    };

    /**
     * MurmurHash3
     */
    @SuppressWarnings("unused")
    HashFunction MURMUR_HASH3 = className -> {
        byte[] data = className.getBytes(StandardCharsets.UTF_8);
        int len = data.length;
        int h = 0x9747b28c;
        int i = 0;

        while (i + 4 <= len) {
            int k = (data[i] & 0xFF)
                    | ((data[i+1] & 0xFF) << 8)
                    | ((data[i+2] & 0xFF) << 16)
                    | ((data[i+3] & 0xFF) << 24);
            k *= 0xcc9e2d51;
            k = Integer.rotateLeft(k, 15);
            k *= 0x1b873593;
            h ^= k;
            h = Integer.rotateLeft(h, 13);
            h = h * 5 + 0xe6546b64;
            i += 4;
        }

        // 尾部字节
        int tail = 0;
        switch (len & 3) {
            case 3: tail ^= (data[i+2] & 0xFF) << 16;
            case 2: tail ^= (data[i+1] & 0xFF) << 8;
            case 1: tail ^= (data[i]   & 0xFF);
                tail *= 0xcc9e2d51;
                tail = Integer.rotateLeft(tail, 15);
                tail *= 0x1b873593;
                h ^= tail;
        }

        // 最终混合（fmix）
        h ^= len;
        h ^= (h >>> 16);
        h *= 0x85ebca6b;
        h ^= (h >>> 13);
        h *= 0xc2b2ae35;
        h ^= (h >>> 16);
        return h;
    };

    int hash(String className);

}
