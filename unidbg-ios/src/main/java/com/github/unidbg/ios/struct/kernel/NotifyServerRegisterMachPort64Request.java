package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterMachPort64Request extends UnidbgStructure {

    public NotifyServerRegisterMachPort64Request(Pointer p) {
        super(p);
    }

    public int pad1;
    public int nameLow;
    public int nameHigh;
    public int pad2;
    public int namelen;
    public int flags;
    public int port;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad1", "nameLow", "nameHigh", "pad2", "namelen", "flags", "port");
    }

}
