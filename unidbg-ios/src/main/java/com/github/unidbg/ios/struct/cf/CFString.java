package com.github.unidbg.ios.struct.cf;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public final class CFString extends UnidbgStructure {

    public CFString(Pointer p) {
        super(p);
        unpack();
    }

    public Pointer isa;
    public Pointer info;
    public Pointer data;
    public int length;

    public String getData() {
        byte[] data = this.data.getByteArray(0, length);
        return new String(data, StandardCharsets.UTF_8);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("isa", "info", "data", "length");
    }

}
