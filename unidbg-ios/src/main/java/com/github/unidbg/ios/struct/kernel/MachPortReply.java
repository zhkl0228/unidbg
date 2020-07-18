package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortReply extends UnicornStructure {

    public MachPortReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public MachMsgPortDescriptor port;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "port");
    }

}
