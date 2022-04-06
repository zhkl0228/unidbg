package com.github.unidbg.linux.signal;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class SigAction extends UnidbgStructure {

    private static final int SA_SIGINFO = 0x00000004;

    public static SigAction create(Emulator<?> emulator, Pointer ptr) {
        if (ptr == null) {
            return null;
        }
        SigAction action;
        if (emulator.is32Bit()) {
            action = new SigAction32(ptr);
        } else {
            action = new SigAction64(ptr);
        }
        action.unpack();
        return action;
    }

    public abstract long getSaHandler();
    public abstract void setSaHandler(long sa_handler);

    public abstract long getSaRestorer();
    public abstract void setSaRestorer(long sa_restorer);

    public boolean needSigInfo() {
        return (getFlags() & SA_SIGINFO) != 0;
    }

    public abstract long getMask();

    public abstract void setMask(long mask);

    public abstract int getFlags();

    public abstract void setFlags(int flags);

    public SigAction(Pointer p) {
        super(p);
    }

}
