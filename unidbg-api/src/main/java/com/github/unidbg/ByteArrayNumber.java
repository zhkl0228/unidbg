package com.github.unidbg;

public class ByteArrayNumber extends Number {

    public final byte[] value;

    public ByteArrayNumber(byte[] value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        throw new AbstractMethodError();
    }

    @Override
    public long longValue() {
        throw new AbstractMethodError();
    }

    @Override
    public float floatValue() {
        throw new AbstractMethodError();
    }

    @Override
    public double doubleValue() {
        throw new AbstractMethodError();
    }
}
