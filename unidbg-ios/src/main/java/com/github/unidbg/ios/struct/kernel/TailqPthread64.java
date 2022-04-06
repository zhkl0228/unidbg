package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TailqPthread64 extends UnidbgStructure {

    public TailqPthread64(Pointer p) {
        super(p);
    }

    public long tqe_next;
    public long tqe_prev;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tqe_next", "tqe_prev");
    }
}
