package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionRecurse32Request extends UnidbgStructure {

    public VmRegionRecurse32Request(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int address;
    public int nestingDepth;
    public int infoCnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "address", "nestingDepth", "infoCnt");
    }

    public long getAddress() {
        return address & 0xffffffffL;
    }

}
