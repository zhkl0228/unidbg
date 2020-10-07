package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.ios.struct.sysctl.TaskDyldInfo;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class TaskDyldInfoReply extends UnidbgStructure {

    public TaskDyldInfoReply(Pointer p) {
        super(p);
        setAlignType(Structure.ALIGN_NONE);
    }

    public NDR_record NDR;
    public int retCode;
    public int task_info_outCnt;
    public TaskDyldInfo dyldInfo;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "task_info_outCnt", "dyldInfo");
    }

}
