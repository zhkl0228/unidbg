package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegion64Reply extends UnidbgStructure {

    public VmRegion64Reply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode1;
    public int retCode2;
    public int pad1;
    public int pad2;
    public long address;
    public long size;
    public int outCnt;
    public VmRegionBasicInfo64 info;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode1", "retCode2", "pad1", "pad2", "address", "size", "outCnt", "info");
    }

}
