package com.github.unidbg.ios.objc;

import com.github.unidbg.Emulator;
import com.sun.jna.Pointer;

public abstract class ObjC {

    public static ObjC getInstance(Emulator emulator) {
        ObjC objc = emulator.get(ObjC.class.getName());
        if (objc == null) {
            objc = new ObjcImpl(emulator);
            emulator.set(ObjC.class.getName(), objc);
        }
        return objc;
    }

    public abstract Pointer getMetaClass(String className);

    public abstract Pointer getClass(String className);

    public abstract Pointer registerName(String selectorName);

}
