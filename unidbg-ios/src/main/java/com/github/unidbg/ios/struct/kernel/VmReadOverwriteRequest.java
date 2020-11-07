package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmReadOverwriteRequest extends UnidbgStructure {

    public VmReadOverwriteRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public long address;
    public long size;
    public long data;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "address", "size", "data");
    }

}
