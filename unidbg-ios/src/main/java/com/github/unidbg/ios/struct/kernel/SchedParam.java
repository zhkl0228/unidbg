package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SchedParam extends UnicornStructure {

    public SchedParam(Pointer p) {
        super(p);
    }

    public int sched_priority;
    public int pad;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sched_priority", "pad");
    }
}
