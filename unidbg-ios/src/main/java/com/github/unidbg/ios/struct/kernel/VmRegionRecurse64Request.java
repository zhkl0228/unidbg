package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionRecurse64Request extends UnidbgStructure {

    public VmRegionRecurse64Request(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public long address;
    public int nestingDepth;
    public int infoCnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "address", "nestingDepth", "infoCnt");
    }

    public long getAddress() {
        return address;
    }

}
