package com.github.unidbg.unix.struct;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeSpec64 extends TimeSpec {

    public TimeSpec64(Pointer p) {
        super(p);
    }

    public long tv_sec; // unsigned long
    public long tv_nsec; // long

    @Override
    public long getTvSec() {
        return tv_sec;
    }

    @Override
    public long getTvNsec() {
        return tv_nsec;
    }

    @Override
    protected void setTv(long tvSec, long tvNsec) {
        this.tv_sec = tvSec;
        this.tv_nsec = tvNsec;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_nsec");
    }

}
