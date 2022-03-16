package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRegionBasicInfo64 extends UnidbgStructure {

    public VmRegionBasicInfo64(byte[] data) {
        super(data);
        setAlignType(ALIGN_NONE);
    }

    public VmRegionBasicInfo64(Pointer p) {
        super(p);
        setAlignType(ALIGN_NONE);
    }

    public int protection;
    public int max_protection;
    public int inheritance;
    public boolean shared;
    public boolean reserved;
    public long offset;
    public int behavior;
    public int user_wired_count;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("protection", "max_protection", "inheritance", "shared", "reserved", "offset", "behavior", "user_wired_count");
    }
}
