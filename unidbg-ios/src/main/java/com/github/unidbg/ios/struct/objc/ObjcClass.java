package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * objc_class
 */
public class ObjcClass extends ObjcObject implements ObjcConstants {

    public static ObjcClass create(Emulator<?> emulator, Pointer pointer) {
        ObjcClass objcClass = new ObjcClass(emulator, pointer);
        objcClass.unpack();
        return objcClass;
    }

    private ObjcClass(Emulator<?> emulator, Pointer p) {
        super(emulator, p);
    }

    public Pointer superClass;
    public Pointer cache;
    public Pointer vtable;
    public Pointer data;

    @Override
    protected List<String> getFieldOrder() {
        List<String> fields = new ArrayList<>(super.getFieldOrder());
        Collections.addAll(fields, "superClass", "cache", "vtable", "data");
        return fields;
    }

    private ClassRW data() {
        UnidbgPointer pointer = (UnidbgPointer) data;
        long address = pointer.peer & ~CLASS_FAST_FLAG_MASK;
        ClassRW classRW = new ClassRW(UnidbgPointer.pointer(emulator, address));
        classRW.unpack();
        return classRW;
    }

    private ClassRO ro() {
        UnidbgPointer pointer = (UnidbgPointer) data;
        long address = pointer.peer & ~CLASS_FAST_FLAG_MASK;
        ClassRO classRO = new ClassRO(UnidbgPointer.pointer(emulator, address));
        classRO.unpack();
        return classRO;
    }

    public boolean isMetaClass() {
        return (data().ro().flags & RO_META) != 0;
    }

    public ObjcClass getMeta() {
        if (isMetaClass()) {
            return this;
        } else {
            return getObjClass();
        }
    }

    private boolean isRealized() {
        return (data().flags & RW_REALIZED) != 0;
    }

    private boolean isFuture() {
        return (data().flags & RO_FUTURE) != 0;
    }

    public String getName() {
        if (isRealized()  ||  isFuture()) {
            return data().ro().name.getString(0);
        } else {
            return ro().name.getString(0);
        }
    }

}
