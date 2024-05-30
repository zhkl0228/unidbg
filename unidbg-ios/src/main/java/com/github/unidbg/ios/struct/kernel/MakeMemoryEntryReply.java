package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class MakeMemoryEntryReply extends UnidbgStructure {

    public MakeMemoryEntryReply(Pointer p) {
        super(p);
    }

    public int status;
    public int object_handle;
    public int retCode;
    public int flags;
    public NDR_record NDR;
    public long outSize;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("status", "object_handle", "retCode", "flags", "NDR", "outSize");
    }

}
