package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.objc.NSArray;
import com.github.unidbg.ios.objc.NSData;
import com.github.unidbg.ios.objc.NSString;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class ObjcObject extends UnidbgStructure {

    public static ObjcObject create(Emulator<?> emulator, Pointer pointer) {
        if (pointer == null) {
            return null;
        } else {
            ObjcObject obj = emulator.is64Bit() ? new ObjcObject64(emulator, pointer) : new ObjcObject32(emulator, pointer);
            obj.unpack();
            return obj;
        }
    }

    final Emulator<?> emulator;

    protected ObjcObject(Emulator<?> emulator, Pointer p) {
        super(p);
        this.emulator = emulator;
    }

    public ObjcClass getObjClass() {
        if (emulator.is64Bit()) {
            UnidbgPointer pointer = getIsa(emulator);
            long address = pointer.peer & 0x1fffffff8L;
            return ObjcClass.create(emulator, UnidbgPointer.pointer(emulator, address));
        } else {
            return ObjcClass.create(emulator, getIsa(emulator));
        }
    }

    public abstract UnidbgPointer getIsa(Emulator<?> emulator);

    public void setInstanceVariable(String name, Object value) {
        ObjC objc = ObjC.getInstance(emulator);
        objc.setInstanceVariable(emulator, this, name, value);
    }

    public UnidbgPointer call(String selectorName, Object... args) {
        ObjC objc = ObjC.getInstance(emulator);
        Pointer selector = objc.registerName(selectorName);
        List<Object> list = new ArrayList<>(args.length + 2);
        list.add(this);
        list.add(selector);
        Collections.addAll(list, args);
        Number number = objc.msgSend(emulator, list.toArray());
        return UnidbgPointer.pointer(emulator, number);
    }

    public ObjcObject callObjc(String selectorName, Object... args) {
        return create(emulator, call(selectorName, args));
    }

    public long callObjcLong(String selectorName, Object... args) {
        UnidbgPointer ptr = call(selectorName, args);
        return ptr == null ? 0 : ptr.peer;
    }

    public int callObjcInt(String selectorName, Object... args) {
        return (int) (callObjcLong(selectorName, args) & 0xffffffffL);
    }

    @SuppressWarnings("unused")
    public ObjcClass toClass() {
        return ObjcClass.create(emulator, getPointer());
    }

    @SuppressWarnings("unused")
    public NSData toNSData() {
        return NSData.create(this);
    }

    public NSString toNSString() {
        return NSString.create(this);
    }

    @SuppressWarnings("unused")
    public NSArray toNSArray() {
        return NSArray.create(this);
    }

    public String getDescription() {
        ObjcObject str = callObjc("description");
        if (str == null) {
            return "<description not available>";
        } else {
            return str.toNSString().getString();
        }
    }

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("isa");
    }

}
