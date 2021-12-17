package com.github.unidbg.linux.thread;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class PThreadInternal extends UnidbgStructure {

    public Pointer next;
    public Pointer prev;
    public int tid;

    public PThreadInternal(Pointer p) {
        super(p);
        unpack();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("next", "prev", "tid");
    }
}
