package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionRequest extends UnidbgStructure {

    public static final int VM_REGION_BASIC_INFO = 10;
    public static final int VM_REGION_BASIC_INFO_COUNT = 8;

    public NDR_record NDR;
    public int address;
    public int flavor;
    public int infoCount; // VM_REGION_BASIC_INFO_COUNT

    public VmRegionRequest(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "address", "flavor", "infoCount");
    }

}
