package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class ClassRO32 extends ClassRO {

    public int ivarLayout;
    public int name;
    public int baseMethods;
    public int baseProtocols;
    public int ivars;
    public int weakIvarLayout;
    public int baseProperties;

    public ClassRO32(Pointer p) {
        super(p);
    }

    @Override
    public UnidbgPointer getNamePointer(Emulator<?> emulator) {
        return UnidbgPointer.pointer(emulator, name);
    }
}
