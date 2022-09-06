package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskBasicInfo64V2 extends UnidbgStructure {

    public TaskBasicInfo64V2(Pointer p) {
        super(p);
    }

    public int suspendCount;  /* suspend count for task */
    public int virtualSize;   /* virtual memory size (bytes) */
    public int residentSize;  /* resident memory size (bytes) */
    public int userTime;      /* total user run time for
                                           terminated threads */
    public int systemTime;    /* total system run time for
                                           terminated threads */
    public int policy;        /* default policy for new threads */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("suspendCount", "virtualSize", "residentSize", "userTime", "systemTime", "policy");
    }

}