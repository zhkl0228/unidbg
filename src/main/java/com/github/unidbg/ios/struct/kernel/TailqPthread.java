package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TailqPthread extends UnicornStructure {

    public TailqPthread(Pointer p) {
        super(p);
    }

    public Pointer tqe_next;
    public Pointer tqe_prev;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tqe_next", "tqe_prev");
    }
}
