package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionReply extends UnidbgStructure {

    public VmRegionReply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int pad1;
    public int retCode;
    public long pad2;
    public int address;
    public int size;
    public int outCnt;
    public VmRegionBasicInfo info;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "pad1", "retCode", "pad2", "address", "size", "outCnt", "info");
    }

}
