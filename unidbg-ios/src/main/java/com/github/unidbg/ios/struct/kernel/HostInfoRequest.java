package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostInfoRequest extends UnidbgStructure {

    public HostInfoRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int flavor;
    public int host_info_out;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "flavor", "host_info_out");
    }
}
