package cn.banny.emulator;

public class StringNumber extends Number {

    public final String value;

    public StringNumber(String value) {
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

    @Override
    public String toString() {
        return value;
    }
}
