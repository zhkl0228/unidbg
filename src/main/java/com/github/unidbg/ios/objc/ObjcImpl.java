package com.github.unidbg.ios.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

class ObjcImpl extends ObjC {

    private final Emulator emulator;
    private final Symbol _objc_getMetaClass;
    private final Symbol _objc_getClass;
    private final Symbol _sel_registerName;

    public ObjcImpl(Emulator emulator) {
        this.emulator = emulator;
        Module module = emulator.getMemory().findModule("libobjc.A.dylib");
        if (module == null) {
            throw new IllegalStateException("libobjc.A.dylib NOT loaded");
        }

        _objc_getMetaClass = module.findSymbolByName("_objc_getMetaClass", false);
        if (_objc_getMetaClass == null) {
            throw new IllegalStateException("_objc_getMetaClass is null");
        }

        _objc_getClass = module.findSymbolByName("_objc_getClass", false);
        if (_objc_getClass == null) {
            throw new IllegalArgumentException("_objc_getClass is null");
        }

        _sel_registerName = module.findSymbolByName("_sel_registerName", false);
        if (_sel_registerName == null) {
            throw new IllegalArgumentException("_sel_registerName is null");
        }
    }

    @Override
    public Pointer getMetaClass(String className) {
        Number number = _objc_getMetaClass.call(emulator, className)[0];
        Pointer pointer;
        if (emulator.is64Bit()) {
            pointer = UnicornPointer.pointer(emulator, number.longValue());
        } else {
            pointer = UnicornPointer.pointer(emulator, number.intValue() & 0xffffffffL);
        }
        if (pointer == null) {
            throw new IllegalArgumentException(className + " NOT found");
        }
        return pointer;
    }

    @Override
    public Pointer getClass(String className) {
        Number number = _objc_getClass.call(emulator, className)[0];
        Pointer pointer;
        if (emulator.is64Bit()) {
            pointer = UnicornPointer.pointer(emulator, number.longValue());
        } else {
            pointer = UnicornPointer.pointer(emulator, number.intValue() & 0xffffffffL);
        }
        if (pointer == null) {
            throw new IllegalArgumentException(className + " NOT found");
        }
        return pointer;
    }

    @Override
    public Pointer registerName(String selectorName) {
        Number number = _sel_registerName.call(emulator, selectorName)[0];
        Pointer pointer;
        if (emulator.is64Bit()) {
            pointer = UnicornPointer.pointer(emulator, number.longValue());
        } else {
            pointer = UnicornPointer.pointer(emulator, number.intValue() & 0xffffffffL);
        }
        if (pointer == null) {
            throw new IllegalStateException(selectorName);
        }
        return pointer;
    }
}
