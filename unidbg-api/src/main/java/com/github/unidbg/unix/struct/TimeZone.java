package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeZone extends UnidbgStructure {

    public TimeZone(Pointer p) {
        super(p);
    }

    public int tz_minuteswest;
    public int tz_dsttime;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tz_minuteswest", "tz_dsttime");
    }

}
