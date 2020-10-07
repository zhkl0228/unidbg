package com.github.unidbg.ios.struct.attr;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ObjId extends UnidbgStructure {

    public ObjId(Pointer p) {
        super(p);
    }

    public int fid_objno;
    public int fid_generation;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("fid_objno", "fid_generation");
    }
}
