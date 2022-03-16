package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

public class ObjcObject64 extends ObjcObject {

    public ObjcObject64(Emulator<?> emulator, Pointer p) {
        super(emulator, p);
    }

    public long isa;

    @Override
    public UnidbgPointer getIsa(Emulator<?> emulator) {
        return UnidbgPointer.pointer(emulator, isa);
    }

}
