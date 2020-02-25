package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ObjcObject extends UnicornStructure {

    public static ObjcObject create(Emulator<?> emulator, Pointer pointer) {
        if (pointer == null) {
            return null;
        } else {
            ObjcObject obj = new ObjcObject(emulator, pointer);
            obj.unpack();
            return obj;
        }
    }

    final Emulator<?> emulator;

    ObjcObject(Emulator<?> emulator, Pointer p) {
        super(p);
        this.emulator = emulator;
    }

    public Pointer isa;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("isa");
    }

    public ObjcClass getObjClass() {
        if (emulator.is64Bit()) {
            UnicornPointer pointer = (UnicornPointer) isa;
            long address = pointer.peer & 0x1fffffff8L;
            return ObjcClass.create(emulator, UnicornPointer.pointer(emulator, address));
        } else {
            return ObjcClass.create(emulator, isa);
        }
    }

    public Pointer call(String selectorName, Object... args) {
        ObjC objc = ObjC.getInstance(emulator);
        Pointer selector = objc.registerName(selectorName);
        List<Object> list = new ArrayList<>(args.length + 2);
        list.add(this);
        list.add(selector);
        Collections.addAll(list, args);
        Number number = objc.msgSend(emulator, list.toArray());
        return UnicornPointer.pointer(emulator, number);
    }

    public ObjcObject callObjc(String selectorName, Object... args) {
        return create(emulator, call(selectorName, args));
    }

    public ObjcClass toClass() {
        return ObjcClass.create(emulator, getPointer());
    }

    public String getDescription() {
        ObjcObject str = callObjc("description");
        return str == null ? null : str.call("UTF8String").getString(0);
    }

}
