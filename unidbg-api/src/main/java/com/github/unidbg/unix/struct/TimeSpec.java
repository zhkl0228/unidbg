package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeSpec extends UnidbgStructure {

    public TimeSpec(Pointer p) {
        super(p);
    }

    public int tv_sec; // unsigned long
    public int tv_nsec; // long

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_nsec");
    }

}
