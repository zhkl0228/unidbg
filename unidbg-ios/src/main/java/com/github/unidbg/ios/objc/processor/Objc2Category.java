package com.github.unidbg.ios.objc.processor;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.pointer.UnidbgPointer;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

final class Objc2Category {

    @SuppressWarnings("unused")
    static Objc2Category read(Map<Long, Objc2Class> classMap, ByteBuffer buffer, long item, MachOModule mm, Emulator<?> emulator) {
        int pos = mm.virtualMemoryAddressToFileOffset(item);
        buffer.position(pos);
        long name = buffer.getLong();
        long clazz = buffer.getLong();
        long instanceMethods = buffer.getLong();
        long classMethods = buffer.getLong();
        long protocols = buffer.getLong();
        long instanceProperties = buffer.getLong();
        long v7 = buffer.getLong();
        long v8 = buffer.getLong();

        pos = mm.virtualMemoryAddressToFileOffset(name);
        buffer.position(pos);
        String categoryName = Utils.readCString(buffer);

        List<Objc2Method> instanceMethodList = Objc2Method.loadMethods(buffer, instanceMethods, mm);
        List<Objc2Method> classMethodList = Objc2Method.loadMethods(buffer, classMethods, mm);
        Objc2Class objc2Class;
        String ownerClassName;
        if (clazz == 0) {
            objc2Class = null;
            UnidbgPointer ptr = UnidbgPointer.pointer(emulator, mm.base + item + 8);
            assert ptr != null;
            UnidbgPointer owner = ptr.getPointer(0);
            if (owner == null) {
                String symbolName = mm.findSymbolNameByAddress(mm.base + item + 8);
                if (symbolName == null) {
                    ownerClassName = "??";
                } else if (symbolName.startsWith("_OBJC_CLASS_$_")) {
                    ownerClassName = symbolName.substring(14);
                } else {
                    ownerClassName = symbolName;
                }
            } else {
                try {
                    ObjcClass objcClass = ObjcClass.create(emulator, owner);
                    ownerClassName = objcClass.getName();
                } catch (BackendException e) {
                    throw new IllegalStateException(e);
                }
            }
        } else {
            boolean valid = mm.validAddress(clazz);
            if (valid) {
                objc2Class = Objc2Class.read(classMap, buffer, clazz, mm);
                if (objc2Class == null) {
                    ownerClassName = "???";
                } else {
                    ownerClassName = objc2Class.getName();
                }
            } else {
                objc2Class = null;
                ownerClassName = "<DEREK BUG Categories!>";
            }
        }
        String cName = ownerClassName + ' ' + '(' + categoryName + ')';
        return new Objc2Category(objc2Class, cName, instanceMethodList, classMethodList);
    }

    final Objc2Class objc2Class;
    final String name;
    final List<Objc2Method> instanceMethodList;
    final List<Objc2Method> classMethodList;

    private Objc2Category(Objc2Class objc2Class, String name, List<Objc2Method> instanceMethodList, List<Objc2Method> classMethodList) {
        this.objc2Class = objc2Class;
        this.name = name;
        this.instanceMethodList = instanceMethodList;
        this.classMethodList = classMethodList;
    }

    @Override
    public String toString() {
        return "Objc2Category{" +
                "name='" + name + '\'' +
                ", objc2Class=" + objc2Class +
                ", instanceMethodList=" + instanceMethodList +
                ", classMethodList=" + classMethodList +
                '}';
    }

}
