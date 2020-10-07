package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionRecurse64Reply extends UnidbgStructure {

    public VmRegionRecurse64Reply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int addressLow;
    public int addressHigh;
    public int sizeLow;
    public int sizeHigh;
    public int nestingDepth;
    public int infoCnt = 7;
    public VmRegionSubMapShortInfo64 info;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "addressLow", "addressHigh", "sizeLow", "sizeHigh", "nestingDepth", "infoCnt", "info");
    }

}
