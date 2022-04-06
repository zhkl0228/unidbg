package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ClockGetTimeReply extends UnidbgStructure {

    public NDR_record NDR;
    public int retCode;
    public int tv_sec;
    public int tv_nsec;

    public ClockGetTimeReply(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "tv_sec", "tv_nsec");
    }

}
