package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterCheckRequest extends UnidbgStructure {

    public NotifyServerRegisterCheckRequest(Pointer p) {
        super(p);
    }

    public int pad;
    public int name;
    public int namelen;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad", "name", "namelen");
    }

}
