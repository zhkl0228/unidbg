package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortTypeReply extends UnicornStructure {

    public MachPortTypeReply(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int retCode;
    public int ptype;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "ptype");
    }

}
