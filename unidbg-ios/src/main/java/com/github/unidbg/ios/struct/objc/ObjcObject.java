package com.github.unidbg.ios.struct.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.objc.NSData;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static com.github.unidbg.ios.objc.Constants.NSUTF8StringEncoding;

public class ObjcObject extends UnidbgStructure {

    public static ObjcObject create(Emulator<?> emulator, Pointer pointer) {
        if (pointer == null) {
            return null;
        } else {
            ObjcObject obj = new ObjcObject(emulator, pointer);
            obj.unpack();
            return obj;
        }
    }

    final Emulator<?> emulator;

    ObjcObject(Emulator<?> emulator, Pointer p) {
        super(p);
        this.emulator = emulator;
    }

    public Pointer isa;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("isa");
    }

    public ObjcClass getObjClass() {
        if (emulator.is64Bit()) {
            UnidbgPointer pointer = (UnidbgPointer) isa;
            long address = pointer.peer & 0x1fffffff8L;
            return ObjcClass.create(emulator, UnidbgPointer.pointer(emulator, address));
        } else {
            return ObjcClass.create(emulator, isa);
        }
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

    @SuppressWarnings("unused")
    public ObjcClass toClass() {
        return ObjcClass.create(emulator, getPointer());
    }

    public NSData toNSData() {
        return NSData.create(this);
    }

    public String getDescription() {
        ObjcObject str = callObjc("description");
        if (str == null) {
            return "<description not available>";
        } else {
            UnidbgPointer pointer = (UnidbgPointer) str.call("lengthOfBytesUsingEncoding:", NSUTF8StringEncoding);
            int length = (int) (pointer.peer & 0x7fffffffL);
            byte[] bytes = str.call("UTF8String").getByteArray(0, length);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

}
