package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmCopyRequest extends UnidbgStructure {

    public VmCopyRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int source_address;
    public int size;
    public int dest_address;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "source_address", "size", "dest_address");
    }
}
