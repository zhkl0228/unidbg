package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterMachPortReply extends UnidbgStructure {

    public NotifyServerRegisterMachPortReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public int ret;
    public int code;
    public int clientId;
    public int status;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "ret", "code", "clientId", "status");
    }
}
