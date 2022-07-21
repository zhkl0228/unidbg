package com.github.unidbg.ios.objc.processor;

import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.ios.MachOModule;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

final class Objc2Class implements ObjcClass {

    private static final long FAST_DATA_MASK = 0x7ffffffffff8L;

    private static final int FAST_IS_SWIFT_LEGACY = 1;
    private static final int FAST_IS_SWIFT_STABLE = 2;

    @SuppressWarnings("unused")
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
        boolean isSwiftClass = (data & (FAST_IS_SWIFT_LEGACY | FAST_IS_SWIFT_STABLE)) != 0;
        data &= FAST_DATA_MASK;
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
    final long superclass;
    final long cache;
    final long vtable;
    final boolean isSwiftClass;
    final int flags;
    private final String name;
    private final List<Objc2Method> methods;

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

    private ObjcClass metaClass;

    void readMetaClass(Map<Long, Objc2Class> classMap, ByteBuffer buffer, MachOModule mm) {
        metaClass = read(classMap, buffer, isa, mm);
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public ObjcClass getMeta() {
        return metaClass;
    }

    @Override
    public ObjcMethod[] getMethods() {
        return methods.toArray(new ObjcMethod[0]);
    }
}
