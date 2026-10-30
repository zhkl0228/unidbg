package com.github.unidbg.pointer;

public interface MemoryWriteListener {

    void onSystemWrite(long addr, byte[] data);

    /** Scalar notification; existing listeners retain their byte-array callback. */
    default void onSystemWriteValue(long addr, long value, int size) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) (value >>> (i * 8));
        }
        onSystemWrite(addr, bytes);
    }

}
