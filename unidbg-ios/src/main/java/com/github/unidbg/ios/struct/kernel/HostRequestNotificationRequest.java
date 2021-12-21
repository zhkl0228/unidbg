package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostRequestNotificationRequest extends UnidbgStructure {

    public int v6;
    public int notify_port;
    public int v8;
    public int v9;
    public NDR_record NDR;
    public int notify_type;

    public HostRequestNotificationRequest(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("v6", "notify_port", "v8", "v9", "NDR", "notify_type");
    }

}
