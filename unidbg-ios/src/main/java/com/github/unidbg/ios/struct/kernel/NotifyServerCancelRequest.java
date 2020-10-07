package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerCancelRequest extends UnidbgStructure {

    public NotifyServerCancelRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int clientId;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "clientId");
    }

}
