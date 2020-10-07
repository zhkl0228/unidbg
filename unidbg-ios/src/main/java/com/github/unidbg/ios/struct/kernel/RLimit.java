package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class RLimit extends UnidbgStructure {

    public RLimit(Pointer p) {
        super(p);
    }

    public long rlim_cur; /* current (soft) limit */
    public long rlim_max; /* maximum value for rlim_cur */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("rlim_cur", "rlim_max");
    }
}
