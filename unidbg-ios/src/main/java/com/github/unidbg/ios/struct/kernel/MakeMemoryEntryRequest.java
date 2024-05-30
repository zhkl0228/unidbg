package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MakeMemoryEntryRequest extends UnidbgStructure {

    public MakeMemoryEntryRequest(Pointer p) {
        super(p);
    }

    public int status;
    public int parent_entry;
    public int ret;
    public int flags;
    public NDR_record NDR;
    public long size;
    public long offset;
    public int permission;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("status", "parent_entry", "ret", "flags", "NDR", "size", "offset", "permission");
    }

}
