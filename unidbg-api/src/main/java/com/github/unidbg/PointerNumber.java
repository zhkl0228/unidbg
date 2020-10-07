package com.github.unidbg;

import com.github.unidbg.pointer.UnidbgPointer;

public class PointerNumber extends Number {

    public final UnidbgPointer value;

    public PointerNumber(UnidbgPointer value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return this.value == null ? 0 : (int) this.value.toUIntPeer();
    }

    @Override
    public long longValue() {
        return this.value == null ? 0L : this.value.peer;
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
