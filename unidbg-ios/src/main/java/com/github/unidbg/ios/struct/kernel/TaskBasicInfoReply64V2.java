package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.ios.struct.sysctl.TaskBasicInfo64V2;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class TaskBasicInfoReply64V2 extends UnidbgStructure {

    public TaskBasicInfoReply64V2(Pointer p) {
        super(p);
        setAlignType(Structure.ALIGN_NONE);
    }

    public NDR_record NDR;
    public int retCode;
    public int task_info_outCnt;
    public TaskBasicInfo64V2 basicInfo;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "task_info_outCnt", "basicInfo");
    }

}
