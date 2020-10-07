package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmCopy64Request extends UnidbgStructure {

    public VmCopy64Request(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public long source_address;
    public long size;
    public long dest_address;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "source_address", "size", "dest_address");
    }
}
