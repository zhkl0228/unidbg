package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SemaphoreCreateReply extends UnidbgStructure {

    public SemaphoreCreateReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public MachMsgPortDescriptor semaphore;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "semaphore");
    }

}
