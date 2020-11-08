package com.github.unidbg.linux.android.dvm.jni;

import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

public class ProxyDvmObject extends DvmObject<Object> {

    private static DvmClass getObjectType(VM vm, Class<?> clazz) {
        Class<?> superClass = clazz.getSuperclass();
        DvmClass[] interfaces = new DvmClass[clazz.getInterfaces().length + (superClass == null ? 0 : 1)];
        int i = 0;
        if (superClass != null) {
            interfaces[i++] = getObjectType(vm, superClass);
        }
        for (Class<?> cc : clazz.getInterfaces()) {
            interfaces[i++] = getObjectType(vm, cc);
        }
        return vm.resolveClass(clazz.getName().replace('.', '/'), interfaces);
    }

    public static DvmObject<?> createObject(VM vm, Object value) {
        if (value instanceof String) {
            return new StringObject(vm, (String) value);
        }
        if (value instanceof byte[]) {
            return new ByteArray(vm, (byte[]) value);
        }

        return new ProxyDvmObject(vm, value);
    }

    private ProxyDvmObject(VM vm, Object value) {
        super(getObjectType(vm, value.getClass()), value);
    }

}
