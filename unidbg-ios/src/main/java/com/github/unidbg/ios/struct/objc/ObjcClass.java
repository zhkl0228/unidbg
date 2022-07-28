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
public abstract class ObjcClass extends ObjcObject implements ObjcConstants, com.github.unidbg.ios.objc.processor.ObjcClass {

    public static ObjcClass create(Emulator<?> emulator, Pointer pointer) {
        if (pointer == null) {
            return null;
        }
        ObjcClass objcClass = emulator.is64Bit() ? new ObjcClass64(emulator, pointer) : new ObjcClass32(emulator, pointer);
        objcClass.unpack();
        return objcClass;
    }

    protected ObjcClass(Emulator<?> emulator, Pointer p) {
        super(emulator, p);
    }

    @Override
    protected List<String> getFieldOrder() {
        List<String> fields = new ArrayList<>(super.getFieldOrder());
        Collections.addAll(fields, "superClass", "cache", "vtable", "data");
        return fields;
    }

    protected abstract UnidbgPointer getDataPointer(Emulator<?> emulator);

    private ClassRW data() {
        UnidbgPointer pointer = getDataPointer(emulator);
        long address = pointer.peer & FAST_DATA_MASK;
        ClassRW classRW = emulator.is64Bit() ? new ClassRW64(UnidbgPointer.pointer(emulator, address)) : new ClassRW32(UnidbgPointer.pointer(emulator, address));
        classRW.unpack();
        return classRW;
    }

    private ClassRO ro() {
        UnidbgPointer pointer = getDataPointer(emulator);
        long address = pointer.peer & FAST_DATA_MASK;
        ClassRO classRO = emulator.is64Bit() ? new ClassRO64(UnidbgPointer.pointer(emulator, address)) : new ClassRO32(UnidbgPointer.pointer(emulator, address));
        classRO.unpack();
        return classRO;
    }

    public boolean isMetaClass() {
        return (data().ro(emulator).flags & RO_META) != 0;
    }

    @Override
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

    @Override
    public String getName() {
        ClassRO ro;
        if (isRealized()  ||  isFuture()) {
            ClassRW data = data();
            ro = data.ro(emulator);
        } else {
            ro = ro();
        }
        Pointer pointer = ro.getNamePointer(emulator);
        if (pointer == null) {
            ClassRW data = data();
            throw new IllegalStateException("data=" + data);
        }
        return pointer.getString(0);
    }

}
