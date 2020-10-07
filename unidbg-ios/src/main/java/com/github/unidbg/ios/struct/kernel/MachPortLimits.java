package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class MachPortLimits extends UnidbgStructure {

    public MachPortLimits(Pointer p) {
        super(p);
    }

    public int mpl_qlimit; /* number of msgs */

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("mpl_qlimit");
    }
}
