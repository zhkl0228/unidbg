package com.github.unidbg.linux.thread;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class PThreadInternal32 extends PThreadInternal {

    public int next;
    public int prev;

    public PThreadInternal32(Pointer p) {
        super(p);
        unpack();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("next", "prev", "tid");
    }
}
