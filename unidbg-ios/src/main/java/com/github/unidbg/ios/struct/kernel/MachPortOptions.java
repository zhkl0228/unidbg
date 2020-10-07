package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MachPortOptions extends UnidbgStructure {

    public MachPortOptions(Pointer p) {
        super(p);
    }

    public int flags; /* Flags defining attributes for port */
    public MachPortLimits mpl; /* Message queue limit for port */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("flags", "mpl");
    }

}
