package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class RLimit64 extends UnidbgStructure {

    public long rlim_cur;
    public long rlim_max;

    public RLimit64(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("rlim_cur", "rlim_max");
    }

}
