package com.github.unidbg.linux.signal;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SigAction64 extends SigAction {

    public SigAction64(Pointer p) {
        super(p);
    }

    public long sa_mask;
    public int sa_flags;

    @Override
    public long getMask() {
        return sa_mask;
    }

    @Override
    public void setMask(long mask) {
        this.sa_mask = mask;
    }

    @Override
    public int getFlags() {
        return sa_flags;
    }

    @Override
    public void setFlags(int flags) {
        this.sa_flags = flags;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sa_handler", "sa_flags", "sa_mask", "sa_restorer");
    }

}
