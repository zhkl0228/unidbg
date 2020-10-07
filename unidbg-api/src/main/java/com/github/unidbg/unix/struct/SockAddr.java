package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SockAddr extends UnidbgStructure {

    public SockAddr(Pointer p) {
        super(p);
    }

    public short sin_family;
    public short sin_port;
    public byte[] sin_addr = new byte[24];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sin_family", "sin_port", "sin_addr");
    }
}
