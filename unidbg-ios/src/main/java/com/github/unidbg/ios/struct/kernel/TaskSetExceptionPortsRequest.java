package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskSetExceptionPortsRequest extends UnidbgStructure {

    public TaskSetExceptionPortsRequest(Pointer p) {
        super(p);
    }

    public int action;
    public int newPort;
    public int ret;
    public int mask;
    public NDR_record NDR;
    public int exceptionMask;
    public int behavior;
    public int newFlavor;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("action", "newPort", "ret", "mask", "NDR", "exceptionMask", "behavior", "newFlavor");
    }

}
