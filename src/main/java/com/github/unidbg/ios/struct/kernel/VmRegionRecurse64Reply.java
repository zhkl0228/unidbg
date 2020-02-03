package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionRecurse64Reply extends UnicornStructure {

    public VmRegionRecurse64Reply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public long address;
    public int size;
    public int nestingDepth;
    public int infoCnt = 7;
    public VmRegionSubMapShortInfo64 info;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "address", "size", "nestingDepth", "infoCnt", "info");
    }

}
