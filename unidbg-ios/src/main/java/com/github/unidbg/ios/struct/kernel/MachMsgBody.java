package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class MachMsgBody extends UnidbgStructure {

    public MachMsgBody(Pointer p) {
        super(p);
    }

    public int msgh_descriptor_count;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("msgh_descriptor_count");
    }
}
