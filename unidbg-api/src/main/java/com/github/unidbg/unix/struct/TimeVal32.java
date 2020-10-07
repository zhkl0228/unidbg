package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeVal32 extends UnidbgStructure {

    public TimeVal32(Pointer p) {
        super(p);
    }

    public int tv_sec;
    public int tv_usec;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_usec");
    }

}
