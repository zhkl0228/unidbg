package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskInfoRequest extends UnicornStructure {

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
