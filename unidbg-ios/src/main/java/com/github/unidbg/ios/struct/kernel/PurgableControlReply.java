package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class PurgableControlReply extends UnidbgStructure {

    public PurgableControlReply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int state;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "state");
    }

}
