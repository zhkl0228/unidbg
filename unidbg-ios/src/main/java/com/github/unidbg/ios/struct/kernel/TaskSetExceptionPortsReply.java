package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskSetExceptionPortsReply extends UnidbgStructure {

    public TaskSetExceptionPortsReply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode");
    }

}
