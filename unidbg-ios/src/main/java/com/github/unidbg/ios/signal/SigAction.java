package com.github.unidbg.ios.signal;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class SigAction extends UnidbgStructure {

    private static final int SA_SIGINFO = 0x0040; /* signal handler with SA_SIGINFO args */

    public static SigAction create(Emulator<?> emulator, Pointer ptr) {
        if (ptr == null) {
            return null;
        } else {
            SigAction action = emulator.is64Bit() ? new SigAction64(ptr) : new SigAction32(ptr);
            action.unpack();
            return action;
        }
    }

    public int sa_mask;
    public int sa_flags;

    public SigAction(Pointer p) {
        super(p);
    }

    public final boolean needSigInfo() {
        return (sa_flags & SA_SIGINFO) != 0;
    }

    public abstract long getSaHandler();
    public abstract void setSaHandler(long sa_handler);

}
