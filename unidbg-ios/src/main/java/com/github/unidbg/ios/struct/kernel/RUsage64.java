package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.unix.struct.TimeVal64;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class RUsage64 extends UnidbgStructure {

    public TimeVal64 ru_utime; /* user time used */
    public TimeVal64 ru_stime; /* system time used */
    public long ru_maxrss;          /* max resident set size */
    public long ru_ixrss;           /* integral shared text memory size */
    public long ru_idrss;           /* integral unshared data size */
    public long ru_isrss;           /* integral unshared stack size */
    public long ru_minflt;          /* page reclaims */
    public long ru_majflt;          /* page faults */
    public long ru_nswap;           /* swaps */
    public long ru_inblock;         /* block input operations */
    public long ru_oublock;         /* block output operations */
    public long ru_msgsnd;          /* messages sent */
    public long ru_msgrcv;          /* messages received */
    public long ru_nsignals;        /* signals received */
    public long ru_nvcsw;           /* voluntary context switches */
    public long ru_nivcsw;          /* involuntary context switches */

    public void fillDefault() {
        ru_utime.tv_sec = 1;
        ru_utime.tv_usec = System.nanoTime();
        ru_stime.tv_sec = 2;
        ru_stime.tv_usec = System.nanoTime();
        ru_maxrss = 0;
        ru_ixrss = 0;
        ru_idrss = 0;
        ru_isrss = 0;
        ru_minflt = 0;
        ru_majflt = 0;
        ru_nswap = 0;
        ru_inblock = 0;
        ru_oublock = 0;
        ru_msgsnd = 0;
        ru_msgrcv = 0;
        ru_nsignals = 0;
        ru_nvcsw = 0;
        ru_nivcsw = 0;
    }

    public RUsage64(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ru_utime", "ru_stime", "ru_maxrss", "ru_ixrss", "ru_idrss", "ru_isrss",
                "ru_minflt", "ru_majflt", "ru_nswap", "ru_inblock", "ru_oublock",
                "ru_msgsnd", "ru_msgrcv", "ru_nsignals", "ru_nvcsw", "ru_nivcsw");
    }
}
