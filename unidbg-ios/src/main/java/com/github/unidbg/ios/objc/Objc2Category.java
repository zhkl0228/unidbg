package com.github.unidbg.ios.objc;

import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.ios.MachOModule;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

final class Objc2Category {

    static Objc2Category read(Map<Long, Objc2Class> classMap, ByteBuffer buffer, long item, MachOModule mm) {
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
        Objc2Class objc2Class = Objc2Class.read(classMap, buffer, clazz, mm);
        String cName = (objc2Class == null ? "??" : objc2Class.name) +
                ' ' + '(' + categoryName + ')';
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
