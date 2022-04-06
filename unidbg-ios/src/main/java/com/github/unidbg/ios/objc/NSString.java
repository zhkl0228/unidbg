package com.github.unidbg.ios.objc;

import com.github.unidbg.PointerArg;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;

import static com.github.unidbg.ios.objc.Constants.NSUTF8StringEncoding;

public class NSString implements PointerArg {

    public static NSString create(ObjcObject object) {
        return object == null ? null : new NSString(object);
    }

    private final ObjcObject object;

    private NSString(ObjcObject object) {
        this.object = object;
    }

    @Override
    public Pointer getPointer() {
        return object.getPointer();
    }

    public String getString() {
        int length = object.callObjcInt("lengthOfBytesUsingEncoding:", NSUTF8StringEncoding);
        byte[] bytes = object.call("UTF8String").getByteArray(0, length);
        return new String(bytes, StandardCharsets.UTF_8);
    }

}
