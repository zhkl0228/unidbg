package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskThreadsReply64 extends UnidbgStructure {

    public TaskThreadsReply64(Pointer p) {
        super(p);
        setAlignType(ALIGN_NONE);
    }

    public MachMsgBody body;
    public long act_list; // pointer
    public int mask;
    public long pad1;
    public int pad2;
    public int act_listCnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "act_list", "mask", "pad1", "pad2", "act_listCnt");
    }

}
