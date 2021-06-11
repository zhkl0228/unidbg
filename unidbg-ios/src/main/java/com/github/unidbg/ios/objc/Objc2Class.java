package com.github.unidbg.ios.objc;

import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.ios.MachOModule;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

final class Objc2Class {

    static Objc2Class read(Map<Long, Objc2Class> classMap, ByteBuffer buffer, long item, MachOModule mm) {
        if (item == 0) {
            return null;
        }

        if (classMap.containsKey(item)) {
            return classMap.get(item);
        }

        int pos = mm.virtualMemoryAddressToFileOffset(item);
        buffer.position(pos);
        long isa = buffer.getLong();
        long superclass = buffer.getLong();
        long cache = buffer.getLong();
        long vtable = buffer.getLong();
        long data = buffer.getLong();
        long reserved1 = buffer.getLong();
        long reserved2 = buffer.getLong();
        long reserved3 = buffer.getLong();
        boolean isSwiftClass = (data & 1) != 0;
        data &= ~1;
        if (data == 0) {
            throw new IllegalStateException("Invalid objc2class data");
        }
        pos = mm.virtualMemoryAddressToFileOffset(data);
        buffer.position(pos);
        int flags = buffer.getInt();
        int instanceStart = buffer.getInt();
        int instanceSize = buffer.getInt();
        int reserved = buffer.getInt();
        long ivarLayout = buffer.getLong();
        long name = buffer.getLong();
        long baseMethods = buffer.getLong();
        long baseProtocols = buffer.getLong();
        long ivars = buffer.getLong();
        long weakIvarLayout = buffer.getLong();
        long baseProperties = buffer.getLong();
        pos = mm.virtualMemoryAddressToFileOffset(name);
        buffer.position(pos);
        String className = Utils.readCString(buffer);
        List<Objc2Method> methods = Objc2Method.loadMethods(buffer, baseMethods, mm);
        Objc2Class objc2Class = new Objc2Class(isa, superclass, cache, vtable, isSwiftClass, flags, className, methods);
        classMap.put(item, objc2Class);
        return objc2Class;
    }

    private final long isa;
    private final long superclass;
    private final long cache;
    private final long vtable;
    private final boolean isSwiftClass;
    private final int flags;
    final String name;
    final List<Objc2Method> methods;

    private Objc2Class(long isa, long superclass, long cache, long vtable, boolean isSwiftClass, int flags, String name, List<Objc2Method> methods) {
        this.isa = isa;
        this.superclass = superclass;
        this.cache = cache;
        this.vtable = vtable;
        this.isSwiftClass = isSwiftClass;
        this.flags = flags;
        this.name = name;
        this.methods = methods;
    }

    @Override
    public String toString() {
        return name;
    }

    Objc2Class metaClass;

    final void readMetaClass(Map<Long, Objc2Class> classMap, ByteBuffer buffer, MachOModule mm) {
        metaClass = read(classMap, buffer, isa, mm);
    }
}
