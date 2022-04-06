package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.github.unidbg.unix.struct.TimeVal32;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ThreadBasicInfo extends UnidbgStructure {

    public ThreadBasicInfo(byte[] data) {
        super(data);
    }

    public ThreadBasicInfo(Pointer p) {
        super(p);
    }

    public TimeVal32 user_time; /* user run time */
    public TimeVal32 system_time; /* system run time */
    public int cpu_usage; /* scaled cpu usage percentage */
    public int policy; /* scheduling policy in effect */
    public int run_state; /* run state (see below) */
    public int flags; /* various flags (see below) */
    public int suspend_count; /* suspend count for thread */
    public int sleep_time; /* number of seconds that thread has been sleeping */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("user_time", "system_time", "cpu_usage", "policy", "run_state", "flags", "suspend_count", "sleep_time");
    }

}
