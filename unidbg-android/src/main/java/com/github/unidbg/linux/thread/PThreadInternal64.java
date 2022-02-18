package com.github.unidbg.linux.thread;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class PThreadInternal64 extends PThreadInternal {

    public long next;
    public long prev;

    public PThreadInternal64(Pointer p) {
        super(p);
        unpack();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("next", "prev", "tid");
    }
}
