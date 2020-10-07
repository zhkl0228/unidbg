package com.github.unidbg.ios.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

class ObjcImpl extends ObjC {

    private final Emulator<?> emulator;

    private final Symbol _objc_msgSend;

    private final Symbol _objc_getMetaClass;
    private final Symbol _objc_getClass;
    private final Symbol _objc_lookUpClass;
    private final Symbol _sel_registerName;

    public ObjcImpl(Emulator<?> emulator) {
        this.emulator = emulator;
        Module module = emulator.getMemory().findModule("libobjc.A.dylib");
        if (module == null) {
            throw new IllegalStateException("libobjc.A.dylib NOT loaded");
        }

        _objc_msgSend = module.findSymbolByName("_objc_msgSend", false);
        if (_objc_msgSend == null) {
            throw new IllegalStateException("_objc_msgSend is null");
        }

        _objc_getMetaClass = module.findSymbolByName("_objc_getMetaClass", false);
        if (_objc_getMetaClass == null) {
            throw new IllegalStateException("_objc_getMetaClass is null");
        }

        _objc_getClass = module.findSymbolByName("_objc_getClass", false);
        if (_objc_getClass == null) {
            throw new IllegalStateException("_objc_getClass is null");
        }

        _objc_lookUpClass = module.findSymbolByName("_objc_lookUpClass", false);
        if (_objc_lookUpClass == null) {
            throw new IllegalStateException("_objc_lookUpClass is null");
        }

        _sel_registerName = module.findSymbolByName("_sel_registerName", false);
        if (_sel_registerName == null) {
            throw new IllegalStateException("_sel_registerName is null");
        }
    }

    @Override
    public ObjcClass getMetaClass(String className) {
        Number number = _objc_getMetaClass.call(emulator, className)[0];
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalArgumentException(className + " NOT found");
        }
        return ObjcClass.create(emulator, pointer);
    }

    @Override
    public ObjcClass getClass(String className) {
        Number number = _objc_getClass.call(emulator, className)[0];
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalArgumentException(className + " NOT found");
        }
        return ObjcClass.create(emulator, pointer);
    }

    @Override
    public ObjcClass lookUpClass(String className) {
        Number number = _objc_lookUpClass.call(emulator, className)[0];
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        return pointer == null ? null : ObjcClass.create(emulator, pointer);
    }

    @Override
    public Pointer registerName(String selectorName) {
        Number number = _sel_registerName.call(emulator, selectorName)[0];
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalStateException(selectorName);
        }
        return pointer;
    }

    @Override
    public Number msgSend(Emulator<?> emulator, Object... args) {
        return _objc_msgSend.call(emulator, args)[0];
    }
}
