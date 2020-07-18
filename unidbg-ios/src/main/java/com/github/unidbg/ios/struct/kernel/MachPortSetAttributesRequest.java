package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortSetAttributesRequest extends UnicornStructure {

    public MachPortSetAttributesRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int name;
    public int flavor;
    public int count;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "name", "flavor", "count");
    }

}
