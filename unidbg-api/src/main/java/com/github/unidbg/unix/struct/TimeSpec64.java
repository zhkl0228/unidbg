package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeSpec64 extends UnidbgStructure {

    public TimeSpec64(Pointer p) {
        super(p);
    }

    public long tv_sec; // unsigned long
    public long tv_nsec; // long

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_nsec");
    }

}
