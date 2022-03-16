package com.github.unidbg.ios.signal;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SigAction32 extends SigAction {

    public SigAction32(Pointer p) {
        super(p);
    }

    public int sa_handler;

    @Override
    public long getSaHandler() {
        return sa_handler;
    }

    @Override
    public void setSaHandler(long sa_handler) {
        this.sa_handler = (int) sa_handler;
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sa_handler", "sa_mask", "sa_flags");
    }
}
