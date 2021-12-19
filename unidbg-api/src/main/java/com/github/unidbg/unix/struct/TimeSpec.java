package com.github.unidbg.unix.struct;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class TimeSpec extends UnidbgStructure {

    public static TimeSpec createTimeSpec(Emulator<?> emulator, Pointer ptr) {
        TimeSpec timeSpec = emulator.is32Bit() ? new TimeSpec32(ptr) : new TimeSpec64(ptr);
        timeSpec.unpack();
        return timeSpec;
    }

    public TimeSpec(Pointer p) {
        super(p);
    }

    public abstract long getTvSec();
    public abstract long getTvNsec();

}
