package com.github.unidbg.ios.signal;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SigAction extends UnidbgStructure {

    private static final int SA_SIGINFO = 0x0040; /* signal handler with SA_SIGINFO args */

    public SigAction(Pointer p) {
        super(p);
    }

    public Pointer sa_handler;
    public int sa_mask;
    public int sa_flags;

    public static SigAction create(Pointer ptr) {
        if (ptr == null) {
            return null;
        } else {
            SigAction action = new SigAction(ptr);
            action.unpack();
            return action;
        }
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sa_handler", "sa_mask", "sa_flags");
    }

    public boolean needSigInfo() {
        return (sa_flags & SA_SIGINFO) != 0;
    }
}
