package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class AslServerMessageRequest extends UnidbgStructure {

    public AslServerMessageRequest(Pointer p) {
        super(p);
    }

    public int pad;
    public int message;
    public int messageCnt;
    public int flags;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad", "message", "messageCnt", "flags");
    }

}
