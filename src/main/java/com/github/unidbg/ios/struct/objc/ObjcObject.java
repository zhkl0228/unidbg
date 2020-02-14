package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class ObjcObject extends UnicornStructure {

    public static ObjcObject create(Pointer pointer) {
        ObjcObject obj = new ObjcObject(pointer);
        obj.unpack();
        return obj;
    }

    ObjcObject(Pointer p) {
        super(p);
    }

    public Pointer isa;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("isa");
    }

    public ObjcClass getObjClass() {
        return ObjcClass.create(isa);
    }

}
