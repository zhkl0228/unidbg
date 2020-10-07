package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterPlainRequest extends UnidbgStructure {

    public NotifyServerRegisterPlainRequest(Pointer p) {
        super(p);
    }

    public int pad;
    public int name;
    public int nameCnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad", "name", "nameCnt");
    }

}
