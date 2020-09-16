package com.github.unidbg.unix.struct;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * Note: Only compatible with libc++, though libstdc++'s std::string is a lot simpler.
 */
public class StdString32 extends StdString {

    StdString32(Pointer p) {
        super(p);
        unpack();
    }

    public byte isTiny;
    public int size;
    public Pointer value;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("isTiny", "size", "value");
    }

    public Pointer getDataPointer() {
        boolean isTiny = (this.isTiny & 1) == 0;
        if (isTiny) {
            return getPointer().share(1);
        } else {
            return value;
        }
    }

    @Override
    public long getDataSize() {
        boolean isTiny = (this.isTiny & 1) == 0;
        if (isTiny) {
            return (this.isTiny & 0xff) >> 1;
        } else {
            return size;
        }
    }
}
