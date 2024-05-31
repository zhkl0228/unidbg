package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachVmMapRequest extends UnidbgStructure {

    public MachVmMapRequest(Pointer p) {
        super(p);
        setAlignType(ALIGN_NONE);
    }

    public int status;
    public int object;
    public int ret;
    public int magic;
    public NDR_record NDR;
    public long address;
    public long size;
    public long mask;
    public int flags;
    public long offset;
    public int copy;
    public int cur_protection;
    public int max_protection;
    public int inheritance;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("status", "object", "ret", "magic", "NDR", "address", "size", "mask", "flags", "offset", "copy", "cur_protection", "max_protection", "inheritance");
    }

}
