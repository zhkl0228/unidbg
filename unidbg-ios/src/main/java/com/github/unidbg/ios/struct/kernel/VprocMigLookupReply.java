package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class VprocMigLookupReply extends UnidbgStructure {

    public VprocMigLookupReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public MachMsgPortDescriptor sp;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "sp");
    }

}
