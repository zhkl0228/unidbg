package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterCheck64Request extends UnidbgStructure {

    public NotifyServerRegisterCheck64Request(Pointer p) {
        super(p);
    }

    public int pad1;
    public int nameLow;
    public int nameHigh;
    public int pad2;
    public int namelen;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad1", "nameLow", "nameHigh", "pad2", "namelen");
    }

}
