package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostInfoReply extends UnidbgStructure {

    public HostInfoReply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int host_info_outCnt = 8;
    public HostInfo host_info_out;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "host_info_outCnt", "host_info_out");
    }

}
