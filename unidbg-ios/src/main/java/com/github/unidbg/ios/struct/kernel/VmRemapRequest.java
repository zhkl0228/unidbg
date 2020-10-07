package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VmRemapRequest extends UnidbgStructure {

    public VmRemapRequest(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public MachMsgPortDescriptor descriptor;
    public NDR_record NDR;

    public long target_address;
    public long size;
    public long mask;
    public int anywhere;
    public int src_address1;
    public int src_address2;
    public int copy;
    public int inheritance;

    public long getSourceAddress() {
        return src_address1 | ((long) src_address2 << 32L);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "descriptor", "NDR", "target_address", "size", "mask", "anywhere", "src_address1", "src_address2", "copy", "inheritance");
    }
}
