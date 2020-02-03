package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerGetStateReply extends UnicornStructure {

    public NotifyServerGetStateReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public int ret;
    public int code;
    public int version;
    public int pid;
    public int status;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "ret", "code", "version", "pid", "status");
    }
}
