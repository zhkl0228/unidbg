package com.github.unidbg.ios.objc;

import com.github.unidbg.PointerArg;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.sun.jna.Pointer;

public class NSData implements PointerArg {

    public static NSData create(ObjcObject object) {
        return object == null ? null : new NSData(object);
    }

    private final ObjcObject object;

    private NSData(ObjcObject object) {
        this.object = object;
    }

    @Override
    public Pointer getPointer() {
        return object.getPointer();
    }

    public byte[] getBytes() {
        int length = object.callObjcInt("length");
        Pointer bytes = getBytesPointer();
        return bytes.getByteArray(0, length);
    }

    public Pointer getBytesPointer() {
        return object.call("bytes");
    }
}
