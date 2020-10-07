package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachMsgPortDescriptor extends UnidbgStructure {

    public MachMsgPortDescriptor(Pointer p) {
        super(p);
    }

    public int name;
    public int pad1;
    public short pad2;
    public byte disposition;
    public byte type;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("name", "pad1", "pad2", "disposition", "type");
    }
}
