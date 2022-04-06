package com.github.unidbg.unix.struct;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class TimeSpec extends UnidbgStructure {

    public static TimeSpec createTimeSpec(Emulator<?> emulator, Pointer ptr) {
        if (ptr == null) {
            return null;
        }
        TimeSpec timeSpec = emulator.is32Bit() ? new TimeSpec32(ptr) : new TimeSpec64(ptr);
        timeSpec.unpack();
        return timeSpec;
    }

    public TimeSpec(Pointer p) {
        super(p);
    }

    public abstract long getTvSec();
    public abstract long getTvNsec();

    public long toMillis() {
        return getTvSec() * 1000L + getTvNsec() / 1000000L;
    }

    public void setMillis(long millis) {
        if (millis < 0) {
            millis = 0;
        }
        long tvSec = millis / 1000L;
        long tvNsec = millis % 1000L * 1000000L;

        setTv(tvSec, tvNsec);
    }

    protected abstract void setTv(long tvSec, long tvNsec);

}
