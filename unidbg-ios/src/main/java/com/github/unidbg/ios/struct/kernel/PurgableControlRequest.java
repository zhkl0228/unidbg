package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class PurgableControlRequest extends UnidbgStructure {

    public PurgableControlRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public long address;
    public int control;
    public int state;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "address", "control", "state");
    }

}
