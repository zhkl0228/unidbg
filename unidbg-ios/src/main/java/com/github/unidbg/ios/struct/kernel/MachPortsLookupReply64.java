package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortsLookupReply64 extends UnidbgStructure {

    public MachPortsLookupReply64(Pointer p) {
        super(p);
    }

    public int retCode;
    public int outPortLow;
    public int outPortHigh;
    public int mask;
    public int reserved1;
    public int reserved2;
    public int reserved3;
    public int cnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("retCode", "outPortLow", "outPortHigh", "mask", "reserved1", "reserved2", "reserved3", "cnt");
    }
}
