package com.github.unidbg.unix.struct;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeSpec32 extends TimeSpec {

    public TimeSpec32(Pointer p) {
        super(p);
    }

    public int tv_sec; // unsigned long
    public int tv_nsec; // long

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
        this.tv_sec = (int) tvSec;
        this.tv_nsec = (int) tvNsec;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_nsec");
    }

}
