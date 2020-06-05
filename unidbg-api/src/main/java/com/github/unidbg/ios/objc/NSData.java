package com.github.unidbg.ios.objc;

import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public class NSData {

    public static NSData create(ObjcObject object) {
        return new NSData(object);
    }

    private final ObjcObject object;

    private NSData(ObjcObject object) {
        this.object = object;
    }

    public byte[] getBytes() {
        UnicornPointer pointer = (UnicornPointer) object.call("length");
        int length = (int) (pointer.peer & 0x7fffffff);
        Pointer bytes = getBytesPointer();
        return bytes.getByteArray(0, length);
    }

    public Pointer getBytesPointer() {
        return object.call("bytes");
    }

}
