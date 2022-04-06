package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionBasicInfo extends UnidbgStructure {

    public VmRegionBasicInfo(byte[] data) {
        super(data);
        setAlignType(ALIGN_NONE);
    }

    public VmRegionBasicInfo(Pointer p) {
        super(p);
        setAlignType(ALIGN_NONE);
    }

    public int protection;
    public int max_protection;
    public int inheritance;
    public boolean shared;
    public boolean reserved;
    public int offset;
    public int behavior;
    public int user_wired_count;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("protection", "max_protection", "inheritance", "shared", "reserved", "offset", "behavior", "user_wired_count");
    }
}
