package com.github.unidbg.linux.signal;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class SigAction extends UnidbgStructure {

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

    public Pointer sa_handler;
    public Pointer sa_restorer;

    public abstract long getMask();

    public abstract void setMask(long mask);

    public abstract long getFlags();

    public abstract void setFlags(long flags);

    public SigAction(Pointer p) {
        super(p);
    }

}
