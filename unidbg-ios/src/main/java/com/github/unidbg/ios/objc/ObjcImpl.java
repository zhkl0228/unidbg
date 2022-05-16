package com.github.unidbg.ios.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class ObjcImpl extends ObjC {

    private final Emulator<?> emulator;

    private final Symbol _objc_msgSend;

    private final Symbol _objc_getMetaClass;
    private final Symbol _objc_getClass;
    private final Symbol _objc_lookUpClass;
    private final Symbol _sel_registerName;
    private final Symbol _class_getMethodImplementation;
    private final Symbol _class_respondsToSelector;
    private final Symbol _object_setInstanceVariable;

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

        _class_getMethodImplementation = module.findSymbolByName("_class_getMethodImplementation", false);
        if (_class_getMethodImplementation == null) {
            throw new IllegalStateException("_class_getMethodImplementation is null");
        }

        _class_respondsToSelector = module.findSymbolByName("_class_respondsToSelector", false);
        if (_class_respondsToSelector == null) {
            throw new IllegalStateException("_class_respondsToSelector is null");
        }

        _object_setInstanceVariable = module.findSymbolByName("_object_setInstanceVariable", false);
        if (_object_setInstanceVariable == null) {
            throw new IllegalStateException("_object_setInstanceVariable is null");
        }
    }

    @Override
    public void setInstanceVariable(Emulator<?> emulator, ObjcObject obj, String name, Object value) {
        if (value instanceof Float) {
            float f = (Float) value;
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putFloat(f);
            buffer.flip();
            value = buffer.getLong();
        } else if (value instanceof Double) {
            double d = (Double) value;
            ByteBuffer buffer = ByteBuffer.allocate(8);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putDouble(d);
            buffer.flip();
            value = buffer.getLong();
        }
        _object_setInstanceVariable.call(emulator, obj, name, value);
    }

    @Override
    public ObjcClass getMetaClass(String className) {
        Number number = _objc_getMetaClass.call(emulator, className);
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalArgumentException(className + " NOT found");
        }
        return ObjcClass.create(emulator, pointer);
    }

    @Override
    public ObjcClass getClass(String className) {
        Number number = _objc_getClass.call(emulator, className);
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalArgumentException(className + " NOT found");
        }
        return ObjcClass.create(emulator, pointer);
    }

    @Override
    public ObjcClass lookUpClass(String className) {
        Number number = _objc_lookUpClass.call(emulator, className);
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        return pointer == null ? null : ObjcClass.create(emulator, pointer);
    }

    @Override
    public Pointer registerName(String selectorName) {
        Number number = _sel_registerName.call(emulator, selectorName);
        Pointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalStateException(selectorName);
        }
        return pointer;
    }

    @Override
    public boolean respondsToSelector(ObjcClass objcClass, String selectorName) {
        Pointer selector = registerName(selectorName);
        Number number = _class_respondsToSelector.call(emulator, objcClass, selector);
        return number.intValue() == 1;
    }

    @Override
    public UnidbgPointer getMethodImplementation(ObjcClass objcClass, String selectorName) {
        Pointer selector = registerName(selectorName);
        Number number = _class_getMethodImplementation.call(emulator, objcClass, selector);
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, number);
        if (pointer == null) {
            throw new IllegalStateException(selectorName);
        }
        return pointer;
    }

    @Override
    public Number msgSend(Emulator<?> emulator, Object... args) {
        return _objc_msgSend.call(emulator, args);
    }

    private ObjcClass cNSString;
    private ObjcClass cNSData;

    @Override
    public NSString newString(String str) {
        if (str == null) {
            return null;
        }
        if (cNSString == null) {
            cNSString = getClass("NSString");
        }
        ObjcObject obj = cNSString.callObjc("stringWithUTF8String:", str);
        return NSString.create(obj);
    }

    @Override
    public NSData newData(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        if (cNSData == null) {
            cNSData = getClass("NSData");
        }
        ObjcObject obj = cNSData.callObjc("dataWithBytes:length:", bytes, bytes.length);
        return NSData.create(obj);
    }
}
