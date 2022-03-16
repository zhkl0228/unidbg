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
        ClassRO ro = new ClassRO64(UnidbgPointer.pointer(emulator, this.ro));
        ro.unpack();
        return ro;
    }
}
