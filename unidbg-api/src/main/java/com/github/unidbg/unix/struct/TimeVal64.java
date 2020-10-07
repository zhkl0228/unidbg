package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeVal64 extends UnidbgStructure {

    public TimeVal64(Pointer p) {
        super(p);
    }

    public long tv_sec;
    public long tv_usec;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_usec");
    }

}
