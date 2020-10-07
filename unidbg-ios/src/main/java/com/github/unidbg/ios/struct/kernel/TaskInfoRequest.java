package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskInfoRequest extends UnidbgStructure {

    public static final int TASK_BASIC_INFO_32 = 4; /* basic information */
    public static final int TASK_BASIC_INFO_64 = 5; /* 64-bit capable basic info */
    public static final int TASK_DYLD_INFO = 17;

    public TaskInfoRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int flavor;
    public int task_info_outCnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "flavor", "task_info_outCnt");
    }
}
