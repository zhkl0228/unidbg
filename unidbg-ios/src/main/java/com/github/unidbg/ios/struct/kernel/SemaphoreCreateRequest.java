package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SemaphoreCreateRequest extends UnidbgStructure {

    public SemaphoreCreateRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int policy;
    public int value;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "policy", "value");
    }

}
