package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class ClassRW64 extends ClassRW {

    public long ro;
    public long methodList;
    public long properties;
    public long protocols;

    public long firstSubclass;
    public long nextSiblingClass;

    public long demangledName;

    public ClassRW64(Pointer p) {
        super(p);
    }

    @Override
    public ClassRO ro(Emulator<?> emulator) {
        long ro = this.ro;
        boolean newObjc = (ro & 1) != 0;
        if (newObjc) { // override objc runtime
            Pointer pointer = UnidbgPointer.pointer(emulator, ro & FAST_DATA_MASK);
            assert pointer != null;
            ro = pointer.getLong(0);
        }
        ClassRO classRO = new ClassRO64(UnidbgPointer.pointer(emulator, ro & FAST_DATA_MASK));
        classRO.unpack();
        return classRO;
    }
}
