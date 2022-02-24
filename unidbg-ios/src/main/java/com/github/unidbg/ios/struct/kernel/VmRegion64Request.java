package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegion64Request extends UnidbgStructure {

    public static final int VM_REGION_BASIC_INFO_64 = 9;
    public static final int VM_REGION_BASIC_INFO_COUNT_64 = 9;

    public NDR_record NDR;
    public long address;
    public int flavor;
    public int infoCount; // VM_REGION_BASIC_INFO_COUNT_64

    public VmRegion64Request(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "address", "flavor", "infoCount");
    }

}
