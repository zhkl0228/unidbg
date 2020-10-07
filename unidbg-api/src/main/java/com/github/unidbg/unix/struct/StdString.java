package com.github.unidbg.unix.struct;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;

public abstract class StdString extends UnidbgStructure implements CharSequence {

    @SuppressWarnings("unused")
    public static StdString createStdString(Emulator<?> emulator, Pointer pointer) {
        if (emulator.is64Bit()) {
            return new StdString64(pointer);
        } else {
            return new StdString32(pointer);
        }
    }

    StdString(Pointer p) {
        super(p);
    }

    public final String getValue() {
        return new String(getData(), StandardCharsets.UTF_8);
    }

    public final byte[] getData() {
        return getDataPointer().getByteArray(0, (int) getDataSize());
    }

    public abstract Pointer getDataPointer();
    public abstract long getDataSize();

    @Override
    public final int length() {
        return getValue().length();
    }

    @Override
    public final char charAt(int index) {
        return getValue().charAt(index);
    }

    @Override
    public final CharSequence subSequence(int start, int end) {
        return getValue().subSequence(start, end);
    }

    @Override
    public final String toString() {
        return getValue();
    }
}
