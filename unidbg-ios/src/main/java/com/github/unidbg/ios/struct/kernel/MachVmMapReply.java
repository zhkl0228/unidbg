package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachVmMapReply extends UnidbgStructure {

    public MachVmMapReply(Pointer p) {
        super(p);
        setAlignType(ALIGN_NONE);
    }

    public NDR_record NDR;
    public int retCode;
    public long address;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "address");
    }

}
