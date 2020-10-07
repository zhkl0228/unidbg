package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortsLookupReply extends UnidbgStructure {

    public MachPortsLookupReply(Pointer p) {
        super(p);
    }

    public int retCode;
    public Pointer outPort;
    public int ret;
    public int mask;
    public int reserved1;
    public int reserved2;
    public int cnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("retCode", "outPort", "ret", "mask", "reserved1", "reserved2", "cnt");
    }
}
