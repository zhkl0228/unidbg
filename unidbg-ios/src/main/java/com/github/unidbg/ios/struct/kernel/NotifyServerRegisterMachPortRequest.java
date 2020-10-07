package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterMachPortRequest extends UnidbgStructure {

    public NotifyServerRegisterMachPortRequest(Pointer p) {
        super(p);
    }

    public int pad;
    public int name;
    public int namelen;
    public int flags;
    public int port;
    public int[] values = new int[4];
    public int token;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad", "name", "namelen", "flags", "port", "values", "token");
    }

}
