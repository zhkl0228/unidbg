package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostRequestNotificationReply extends UnidbgStructure {

    public HostRequestNotificationReply(Pointer p) {
        super(p);
    }

    public int v6;
    public int v7;
    public int retCode;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("v6", "v7", "retCode");
    }
}
